// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Polyglot code-structure scanner backed by tree-sitter for non-Rust files.
//!
//! `CORECRUXD_POLYGLOT_V3` long-tail precision contract:
//! - C# methods use `Namespace.Class.Method`; absent member modifiers are private and
//!   absent top-level type modifiers are internal, so both serialize as non-public.
//! - Ruby instance methods use `Module::Class#method` and `def self.x` uses
//!   `Module::Class.x`. Bare `private`/`protected` section markers are tracked, but
//!   metaprogrammed visibility (`private :name`, `send`, refinements) is deliberately
//!   not inferred because Ruby visibility is dynamic.
//! - PHP callables use `Namespace\\Class::method` / `Namespace\\function`.
//! - ASP.NET recognition requires a controller base or `[ApiController]`; client HTTP
//!   calls never enter the attribute-only detector.
//! - Rails scanning is restricted to `config/routes.rb`. It accepts static literal
//!   verb routes, static `namespace`/`scope` blocks, multiple resource names, and
//!   `only:`/`except:` resource filters. Unfiltered resources expand to seven
//!   conventional REST actions (PATCH is the single update route). Conditional or
//!   dynamic declarations are diagnostics, not guessed routes; arbitrary Ruby DSL
//!   metaprogramming is outside the precision bar.
//! - Laravel scanning is restricted to `routes/*.php`. It accepts static `Route::verb`,
//!   array/closure handlers, array and fluent groups, seven-route `resource` expansion
//!   (PUT is the single update route), and five-route `apiResource` expansion. Custom
//!   macros and dynamic arguments are outside the precision bar and are skipped or
//!   diagnosed.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tree_sitter::{Node, ParseOptions, Parser};

use crate::workspace_scan::{
    parse_file_doc_header, walk_dir, CrateInfo, DepEdge, FileInfo, FileReference, RouteHit, ScanDiagnostics, ScanError,
    ScanStats, SymbolInfo, UnresolvedRoute, V3SkippedFile, WorkspaceScan,
};

const POLYGLOT_V2_ENV: &str = "CORECRUXD_POLYGLOT_V2";
const POLYGLOT_V3_ENV: &str = "CORECRUXD_POLYGLOT_V3";
pub const POLYGLOT_AST_MAX_DEPTH: usize = 512;
const MAX_DJANGO_EXPANSION_STATES: usize = 1024;
pub const POLYGLOT_JS_MAX_BYTES: usize = 1024 * 1024;
pub const POLYGLOT_JS_MAX_LINE_BYTES: usize = 10_000;
pub const POLYGLOT_JAVA_MAX_BYTES: usize = 1024 * 1024;
pub const POLYGLOT_JAVA_MAX_LINE_BYTES: usize = 10_000;
pub const POLYGLOT_C_MAX_BYTES: usize = 1024 * 1024;
pub const POLYGLOT_C_MAX_LINE_BYTES: usize = 10_000;
pub const POLYGLOT_CPP_MAX_BYTES: usize = 1024 * 1024;
pub const POLYGLOT_CPP_MAX_LINE_BYTES: usize = 10_000;
pub const POLYGLOT_CSHARP_MAX_BYTES: usize = 1024 * 1024;
pub const POLYGLOT_CSHARP_MAX_LINE_BYTES: usize = 10_000;
pub const POLYGLOT_RUBY_MAX_BYTES: usize = 1024 * 1024;
pub const POLYGLOT_RUBY_MAX_LINE_BYTES: usize = 10_000;
pub const POLYGLOT_SWIFT_MAX_BYTES: usize = 1024 * 1024;
pub const POLYGLOT_SWIFT_MAX_LINE_BYTES: usize = 10_000;
pub const POLYGLOT_PHP_MAX_BYTES: usize = 1024 * 1024;
pub const POLYGLOT_PHP_MAX_LINE_BYTES: usize = 10_000;

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

pub fn polyglot_v2_enabled_from_env() -> bool {
    crate::workspace_scan_manifests::env_flag_enabled(POLYGLOT_V2_ENV)
}

pub fn polyglot_v3_enabled() -> bool {
    crate::workspace_scan_manifests::env_flag_enabled(POLYGLOT_V3_ENV)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LanguageKind {
    Rust,
    TypeScript,
    Tsx,
    Python,
    Vue,
    Svelte,
    Go,
    Java,
    C,
    Cpp,
    CSharp,
    Ruby,
    Swift,
    Php,
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
    django_includes: Vec<DjangoIncludeCandidate>,
    unresolved_routes: Vec<UnresolvedRoute>,
    ast_depth_limit_hits: usize,
    /// `Some(reason)` when the tree-sitter parse refused this file outright or
    /// produced a tree containing ERROR nodes.
    ///
    /// D-24: tree-sitter is error-tolerant, so a broken `.ts`/`.py`/`.java`
    /// file yields a tree full of ERROR nodes and therefore no symbols —
    /// byte-identical to an empty file. Nothing recorded the failure.
    parse_error: Option<String>,
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
    framework: Option<String>,
    source_file: String,
    source_line: usize,
}

#[derive(Debug, Clone)]
enum RouteHandler {
    Named(String),
    Inline,
    Resolved { name: String, file: String, line: usize },
    Django(String),
}

#[derive(Debug, Clone)]
struct DjangoIncludeCandidate {
    prefix: String,
    target: DjangoIncludeTarget,
    source_file: String,
    source_line: usize,
}

#[derive(Debug, Clone)]
enum DjangoIncludeTarget {
    Module(String),
    Dynamic(String),
}

impl ExtractedFile {
    fn push_dep(&mut self, dep: DepEdge) {
        let bytes = dep
            .from_crate
            .len()
            .saturating_add(dep.from_file.len())
            .saturating_add(dep.to_module.len())
            .saturating_add(dep.raw.len());
        if crate::repo_scan_policy::charge_generated_work(1, bytes, "polyglot dependency intermediate").is_ok() {
            self.deps.push(dep);
        }
    }

    fn push_call(&mut self, call: CallSite) {
        let bytes = call
            .name
            .len()
            .saturating_add(call.from_symbol.as_deref().map_or(0, str::len));
        if crate::repo_scan_policy::charge_generated_work(1, bytes, "polyglot call intermediate").is_ok() {
            self.calls.push(call);
        }
    }

    fn push_route(&mut self, route: RouteCandidate) {
        let handler_bytes = match &route.handler {
            RouteHandler::Inline => 0,
            RouteHandler::Named(name) | RouteHandler::Django(name) => name.len(),
            RouteHandler::Resolved { name, file, .. } => name.len().saturating_add(file.len()),
        };
        let bytes = route
            .method
            .len()
            .saturating_add(route.path.len())
            .saturating_add(route.framework.as_deref().map_or(0, str::len))
            .saturating_add(route.source_file.len())
            .saturating_add(handler_bytes);
        if crate::repo_scan_policy::charge_generated_work(1, bytes, "polyglot route intermediate").is_ok() {
            self.routes.push(route);
        }
    }

    fn push_django_include(&mut self, include: DjangoIncludeCandidate) {
        let target_bytes = match &include.target {
            DjangoIncludeTarget::Module(target) | DjangoIncludeTarget::Dynamic(target) => target.len(),
        };
        let bytes = include
            .prefix
            .len()
            .saturating_add(include.source_file.len())
            .saturating_add(target_bytes);
        if crate::repo_scan_policy::charge_generated_work(1, bytes, "Django include intermediate").is_ok() {
            self.django_includes.push(include);
        }
    }

    fn push_unresolved_route(&mut self, route: UnresolvedRoute) {
        let bytes = route
            .method
            .len()
            .saturating_add(route.path.len())
            .saturating_add(route.handler_fn.len())
            .saturating_add(route.source_file.len())
            .saturating_add(route.reason.len());
        if crate::repo_scan_policy::charge_generated_work(1, bytes, "unresolved route intermediate").is_ok() {
            self.unresolved_routes.push(route);
        }
    }
}

#[derive(Debug, Default)]
struct AstWalkGuard {
    depth_limit_hits: usize,
}

impl AstWalkGuard {
    fn allow_depth(&mut self, depth: usize) -> bool {
        if crate::repo_scan_policy::check_deadline().is_err()
            || crate::repo_scan_policy::charge_generated_work(1, 32, "polyglot AST walk node").is_err()
        {
            return false;
        }
        if depth <= POLYGLOT_AST_MAX_DEPTH {
            return true;
        }
        self.depth_limit_hits += 1;
        false
    }
}

fn parse_with_scan_budget(parser: &mut Parser, src: &str) -> Result<Option<tree_sitter::Tree>, ScanError> {
    crate::repo_scan_policy::check_deadline()?;
    crate::repo_scan_policy::charge_source_parse_work(src, "polyglot AST parser work")?;
    let bytes = src.as_bytes();
    let mut progress = |_state: &tree_sitter::ParseState| match crate::repo_scan_policy::check_deadline() {
        Ok(()) => ControlFlow::Continue(()),
        Err(_) => ControlFlow::Break(()),
    };
    let options = ParseOptions::new().progress_callback(&mut progress);
    let tree = parser.parse_with_options(
        &mut |offset, _point| bytes.get(offset..).unwrap_or_default(),
        None,
        Some(options),
    );
    crate::repo_scan_policy::check_deadline()?;
    Ok(tree)
}

#[cfg(test)]
pub fn run_repo_scan_at(root: &Path) -> Result<WorkspaceScan, ScanError> {
    let policy = crate::repo_scan_policy::RepoScanPolicy::for_exact_root(root)?;
    run_repo_scan_at_with_policy(root, &policy)
}

pub fn run_repo_scan_at_with_policy(
    root: &Path,
    policy: &crate::repo_scan_policy::RepoScanPolicy,
) -> Result<WorkspaceScan, ScanError> {
    policy.execute(root, run_repo_scan_in_context)
}

pub fn run_repo_scan_in_context(root: &Path) -> Result<WorkspaceScan, ScanError> {
    let options = PolyglotScanOptions::from_env();
    let mut scan = if should_use_rust_workspace_scan_with_options(root, options)? {
        crate::workspace_scan::run_scan_at_in_context(root)?
    } else if has_rust_workspace(root)? {
        // Cargo workspace + polyglot files: scan the cargo tree natively so
        // crate structure and route extraction survive, then merge the
        // tree-sitter extraction of the non-Rust files on top. Without this a
        // single stray .ts/.py file used to flatten a 28-crate workspace into
        // one package with zero routes.
        let mut scan = crate::workspace_scan::run_scan_at_in_context(root)?;
        let poly = run_polyglot_scan_inner(root, false, options)?;
        merge_polyglot_scan(&mut scan, poly, options)?;
        scan
    } else {
        run_polyglot_scan_inner(root, true, options)?
    };
    crate::workspace_scan_manifests::attach_external_deps_if_enabled(root, &mut scan)?;
    Ok(scan)
}

pub fn has_rust_workspace(root: &Path) -> Result<bool, ScanError> {
    let manifest = root.join("Cargo.toml");
    if crate::repo_scan_policy::scan_file_metadata(&manifest)?.is_none() {
        return Ok(false);
    }
    has_supported_file(root, &[Some("rs")])
}

#[cfg(test)]
pub fn should_use_rust_workspace_scan(root: &Path) -> Result<bool, ScanError> {
    should_use_rust_workspace_scan_with_options(root, PolyglotScanOptions::from_env())
}

fn should_use_rust_workspace_scan_with_options(root: &Path, options: PolyglotScanOptions) -> Result<bool, ScanError> {
    Ok(has_rust_workspace(root)? && !has_polyglot_non_rust_files(root, options)?)
}

/// Fold a rust-excluded polyglot scan into a native Rust workspace scan.
/// Crates, routes, stubs and dead-code stay authoritative from the Rust side;
/// files/symbols/deps are unioned and the stats re-rolled from the merged
/// contents.
fn merge_polyglot_scan(
    scan: &mut WorkspaceScan,
    poly: WorkspaceScan,
    options: PolyglotScanOptions,
) -> Result<(), ScanError> {
    let existing: std::collections::BTreeSet<String> = scan.crates.iter().map(|c| c.name.clone()).collect();
    scan.crates
        .extend(poly.crates.into_iter().filter(|c| !existing.contains(&c.name)));
    scan.files.extend(poly.files);
    scan.symbols.extend(poly.symbols);
    scan.deps.extend(poly.deps);
    if options.v2_enabled || options.v3_enabled {
        scan.routes.extend(poly.routes);
        scan.diagnostics
            .unresolved_routes
            .extend(poly.diagnostics.unresolved_routes);
    }
    // The field predates baseline TS and V2 JS pre-parse guards, but those
    // guards now use the same durable omission diagnostic. Preserve it even
    // when V3 extraction is disabled so hybrid Rust scans cannot look complete.
    scan.diagnostics
        .v3_skipped_files
        .extend(poly.diagnostics.v3_skipped_files);
    scan.duration_ms += poly.duration_ms;
    scan.finished_at_unix_ms = scan.finished_at_unix_ms.max(poly.finished_at_unix_ms);
    roll_up_stats(scan)
}

#[cfg(test)]
pub fn run_polyglot_scan_at(root: &Path) -> Result<WorkspaceScan, ScanError> {
    let policy = crate::repo_scan_policy::RepoScanPolicy::for_exact_root(root)?;
    policy.execute(root, |canonical| {
        run_polyglot_scan_inner(canonical, true, PolyglotScanOptions::from_env())
    })
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
    for (file_index, (abs, lang)) in files.into_iter().enumerate() {
        if file_index % 256 == 0 {
            crate::repo_scan_policy::check_deadline()?;
        }
        if let Some(file) =
            extract_file_recording_skips(root, &abs, lang, &package_name, options, &mut v3_skipped_files)?
        {
            crate::repo_scan_policy::charge_generated_work(
                1,
                file.rel_path
                    .len()
                    .saturating_add(file.package_name.len())
                    .saturating_add(file.module_path.len())
                    .saturating_add(file.doc_summary.as_deref().map_or(0, str::len))
                    .saturating_add(file.doc_full.as_deref().map_or(0, str::len))
                    .saturating_add(std::mem::size_of::<ExtractedFile>()),
                "polyglot extracted-file collection",
            )?;
            extracted.push(file);
        }
    }

    let mut scan = WorkspaceScan {
        scan_id: format!("ws_{started_ms}_{}", uuid::Uuid::new_v4().simple()),
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

    for (file_index, file) in extracted.iter().enumerate() {
        if file_index % 256 == 0 {
            crate::repo_scan_policy::check_deadline()?;
        }
        crate::repo_scan_policy::charge_generated_work(
            1,
            file.rel_path
                .len()
                .saturating_add(file.package_name.len())
                .saturating_add(file.module_path.len())
                .saturating_add(file.doc_full.as_deref().map_or(0, str::len)),
            "scan output",
        )?;
        crate::repo_scan_policy::charge_generated_work(1, file.rel_path.len(), "polyglot file-path index")?;
        file_idx_by_path.insert(file.rel_path.clone(), scan.files.len());
        let define_bytes = file.symbols.iter().map(|symbol| symbol.name.len()).sum();
        crate::repo_scan_policy::charge_generated_work(
            file.symbols.len(),
            define_bytes,
            "polyglot file definition output",
        )?;
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
        for dep in &file.deps {
            crate::repo_scan_policy::charge_generated_work(
                1,
                dep.from_crate
                    .len()
                    .saturating_add(dep.from_file.len())
                    .saturating_add(dep.to_module.len())
                    .saturating_add(dep.raw.len()),
                "polyglot dependency output",
            )?;
            scan.deps.push(dep.clone());
        }
        for (symbol_index, symbol) in file.symbols.iter().enumerate() {
            if symbol_index % 256 == 0 {
                crate::repo_scan_policy::check_deadline()?;
            }
            crate::repo_scan_policy::charge_generated_work(
                2,
                symbol
                    .name
                    .len()
                    .saturating_add(symbol.file_rel_path.len())
                    .saturating_mul(2),
                "polyglot symbol index and output",
            )?;
            symbol_by_name
                .entry(symbol.name.clone())
                .or_default()
                .push(symbol.clone());
            scan.symbols.push(symbol.clone());
        }
    }

    resolve_polyglot_references(&mut scan, &extracted, &file_idx_by_path, &symbol_by_name)?;
    build_referenced_by(&mut scan)?;
    scan.crates = package_infos(root, &scan, &package_name)?;
    if options.v2_enabled || options.v3_enabled {
        resolve_polyglot_routes(&mut scan, &extracted, &symbol_by_name)?;
    }
    if options.v3_enabled {
        collect_file_based_routes(root, &extracted, &mut scan)?;
    }
    roll_up_stats(&mut scan)?;
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
    let mut discovery_error = None;
    walk_dir(root, root, &mut |rel, abs| {
        if discovery_error.is_some() {
            return;
        }
        if should_skip_generated_polyglot_file(rel, options) {
            return;
        }
        if let Some(lang) = language_for_path(abs, options) {
            if include_rust || lang != LanguageKind::Rust {
                if let Err(error) = crate::repo_scan_policy::charge_generated_work(
                    1,
                    abs.as_os_str().as_encoded_bytes().len(),
                    "polyglot supported-file index",
                ) {
                    discovery_error = Some(error);
                    return;
                }
                files.push((abs.to_path_buf(), lang));
            }
        }
    })?;
    if let Some(error) = discovery_error {
        return Err(error);
    }
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
        "svelte" if options.v3_enabled => Some(LanguageKind::Svelte),
        "js" | "mjs" | "cjs" if options.v2_enabled || options.v3_enabled => Some(LanguageKind::TypeScript),
        "jsx" if options.v2_enabled || options.v3_enabled => Some(LanguageKind::Tsx),
        "go" if options.v2_enabled => Some(LanguageKind::Go),
        "java" if options.v3_enabled => Some(LanguageKind::Java),
        "c" if options.v3_enabled => Some(LanguageKind::C),
        // Ambiguous .h headers enter as C, then a deterministic source sniff
        // upgrades obvious namespace/template/extern-C++ headers after reading.
        // Explicit C++ header suffixes map directly to C++.
        "h" if options.v3_enabled => Some(LanguageKind::C),
        "cpp" | "cc" | "cxx" | "hpp" | "hh" | "hxx" if options.v3_enabled => Some(LanguageKind::Cpp),
        "cs" if options.v3_enabled => Some(LanguageKind::CSharp),
        "rb" if options.v3_enabled => Some(LanguageKind::Ruby),
        "swift" if options.v3_enabled => Some(LanguageKind::Swift),
        "php" if options.v3_enabled => Some(LanguageKind::Php),
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
    let is_v2_js = (options.v2_enabled || options.v3_enabled) && matches!(extension, "js" | "jsx" | "mjs" | "cjs");
    let is_v3_source = options.v3_enabled
        && matches!(
            extension,
            "svelte" | "java" | "c" | "h" | "cpp" | "cc" | "cxx" | "hpp" | "hh" | "hxx" | "cs" | "rb" | "swift" | "php"
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

/// Best-effort language id from a path, for `ParseFailure::language`.
fn language_id_for_path(rel_path: &str) -> &'static str {
    match rel_path.rsplit_once('.').map(|(_, ext)| ext) {
        Some("ts") => "typescript",
        Some("tsx") => "tsx",
        Some("js") | Some("jsx") | Some("mjs") | Some("cjs") => "javascript",
        Some("py") => "python",
        Some("go") => "go",
        Some("java") => "java",
        Some("c") | Some("h") => "c",
        Some("cc") | Some("cpp") | Some("cxx") | Some("hpp") => "cpp",
        Some("cs") => "csharp",
        Some("rb") => "ruby",
        Some("swift") => "swift",
        Some("php") => "php",
        Some("vue") => "vue",
        Some("rs") => "rust",
        _ => "unknown",
    }
}

/// Parse `src`, recording on `file` when the parser refused it outright or
/// produced a tree containing ERROR nodes. See `ExtractedFile::parse_error`.
fn parse_or_note(parser: &mut Parser, src: &str, file: &mut ExtractedFile) -> Option<tree_sitter::Tree> {
    let Some(tree) = parser.parse(src, None) else {
        file.parse_error = Some("parser returned no tree".to_string());
        return None;
    };
    if tree.root_node().has_error() && file.parse_error.is_none() {
        file.parse_error = Some("source contains syntax errors; extracted symbols are incomplete".to_string());
    }
    Some(tree)
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
    if let Some(reason) = pathological_v3_size_skip_reason(&rel_path, abs, lang, options)? {
        crate::repo_scan_policy::charge_generated_work(
            1,
            rel_path.len().saturating_add(reason.len()),
            "polyglot skipped-file diagnostic",
        )?;
        v3_skipped_files.push(V3SkippedFile {
            rel_path,
            reason: reason.to_string(),
        });
        return Ok(None);
    }
    let src = crate::workspace_scan::read_scan_to_string(abs)?;
    if should_skip_pathological_v2_js(&rel_path, &src, options) {
        return Ok(None);
    }
    let lang = language_for_source(lang, abs, &src);
    if let Some(reason) = pathological_v3_source_skip_reason(&rel_path, &src, lang, options) {
        crate::repo_scan_policy::charge_generated_work(
            1,
            rel_path.len().saturating_add(reason.len()),
            "polyglot skipped-file diagnostic",
        )?;
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
        django_includes: Vec::new(),
        unresolved_routes: Vec::new(),
        ast_depth_limit_hits: 0,
        parse_error: None,
    };
    let mut guard = AstWalkGuard::default();

    match lang {
        LanguageKind::Rust => extract_rust_file(&src, &mut file, &mut guard)?,
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
        LanguageKind::Svelte => {}
        LanguageKind::Go => extract_go_file(&src, &mut file, options, &mut guard)?,
        LanguageKind::Java => extract_java_file(&src, &mut file, &mut guard)?,
        LanguageKind::C => extract_c_family_file(&src, &mut file, false, &mut guard)?,
        LanguageKind::Cpp => extract_c_family_file(&src, &mut file, true, &mut guard)?,
        LanguageKind::CSharp => extract_csharp_file(&src, &mut file, &mut guard)?,
        LanguageKind::Ruby => extract_ruby_file(&src, &mut file, &mut guard)?,
        LanguageKind::Swift => extract_swift_file(&src, &mut file, &mut guard)?,
        LanguageKind::Php => extract_php_file(&src, &mut file, &mut guard)?,
    }
    crate::repo_scan_policy::check_deadline()?;
    file.ast_depth_limit_hits = guard.depth_limit_hits;
    if file.ast_depth_limit_hits > 0 {
        return Err(ScanError::Policy(format!(
            "polyglot AST walk for {} exceeded depth {}; partial extraction is not persisted",
            file.rel_path, POLYGLOT_AST_MAX_DEPTH
        )));
    }
    Ok(Some(file))
}

fn should_skip_pathological_v2_js(rel_path: &str, src: &str, options: PolyglotScanOptions) -> bool {
    if !(options.v2_enabled || options.v3_enabled) || !is_v2_js_path(rel_path) {
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
        LanguageKind::TypeScript | LanguageKind::Tsx | LanguageKind::Python | LanguageKind::Vue | LanguageKind::Go => {
            Some((POLYGLOT_JS_MAX_BYTES, POLYGLOT_JS_MAX_LINE_BYTES))
        }
        LanguageKind::Java => Some((POLYGLOT_JAVA_MAX_BYTES, POLYGLOT_JAVA_MAX_LINE_BYTES)),
        LanguageKind::C => Some((POLYGLOT_C_MAX_BYTES, POLYGLOT_C_MAX_LINE_BYTES)),
        LanguageKind::Cpp => Some((POLYGLOT_CPP_MAX_BYTES, POLYGLOT_CPP_MAX_LINE_BYTES)),
        LanguageKind::Svelte => None,
        LanguageKind::CSharp => Some((POLYGLOT_CSHARP_MAX_BYTES, POLYGLOT_CSHARP_MAX_LINE_BYTES)),
        LanguageKind::Ruby => Some((POLYGLOT_RUBY_MAX_BYTES, POLYGLOT_RUBY_MAX_LINE_BYTES)),
        LanguageKind::Swift => Some((POLYGLOT_SWIFT_MAX_BYTES, POLYGLOT_SWIFT_MAX_LINE_BYTES)),
        LanguageKind::Php => Some((POLYGLOT_PHP_MAX_BYTES, POLYGLOT_PHP_MAX_LINE_BYTES)),
        _ => None,
    }
}

fn source_limits_enabled(lang: LanguageKind, options: PolyglotScanOptions) -> bool {
    matches!(
        lang,
        LanguageKind::TypeScript | LanguageKind::Tsx | LanguageKind::Python | LanguageKind::Vue
    ) || (lang == LanguageKind::Go && options.v2_enabled)
        || options.v3_enabled
}

fn pathological_v3_size_skip_reason(
    rel_path: &str,
    abs: &Path,
    lang: LanguageKind,
    options: PolyglotScanOptions,
) -> Result<Option<&'static str>, ScanError> {
    if !source_limits_enabled(lang, options) {
        return Ok(None);
    }
    let Some((max_bytes, _)) = v3_source_limits(lang) else {
        return Ok(None);
    };
    let Some(metadata) = crate::repo_scan_policy::scan_file_metadata_for_admission(abs)? else {
        tracing::warn!(file = %rel_path, "polyglot v3 non-regular file skipped before reading");
        return Ok(Some("non_regular_file"));
    };
    let byte_len = metadata.len();
    if byte_len <= max_bytes as u64 {
        return Ok(None);
    }
    tracing::warn!(
        file = %rel_path,
        bytes = byte_len,
        max_bytes,
        "polyglot v3 file skipped before reading or parsing"
    );
    Ok(Some("max_bytes"))
}

fn pathological_v3_source_skip_reason(
    rel_path: &str,
    src: &str,
    lang: LanguageKind,
    options: PolyglotScanOptions,
) -> Option<&'static str> {
    if !source_limits_enabled(lang, options) {
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
                (b'#', _) if matches!(lang, LanguageKind::Ruby | LanguageKind::Php) => {
                    state = LexState::LineComment;
                }
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
                        update_source_delimiter_depth(bytes, index, lang, &mut depth, &mut angle_depth, &mut max_depth);
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
                    update_source_delimiter_depth(bytes, index, lang, &mut depth, &mut angle_depth, &mut max_depth);
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
    bytes: &[u8],
    index: usize,
    lang: LanguageKind,
    depth: &mut usize,
    angle_depth: &mut usize,
    max_depth: &mut usize,
) {
    let byte = bytes[index];
    match byte {
        b'(' | b'[' | b'{' => {
            *depth += 1;
            *max_depth = (*max_depth).max(*depth);
            if byte == b'{' {
                *angle_depth = 0;
            }
        }
        b')' | b']' | b'}' => {
            *depth = depth.saturating_sub(1);
            if byte == b'}' {
                *angle_depth = 0;
            }
        }
        b'<' if tracks_generic_angle_nesting(lang) && looks_like_generic_open(bytes, index) => {
            *angle_depth += 1;
            *max_depth = (*max_depth).max(*angle_depth);
        }
        b'>' if tracks_generic_angle_nesting(lang) && *angle_depth > 0 => {
            *angle_depth = angle_depth.saturating_sub(1);
        }
        b';' if tracks_generic_angle_nesting(lang) => *angle_depth = 0,
        b'&' if tracks_generic_angle_nesting(lang) && bytes.get(index + 1) == Some(&b'&') => {
            *angle_depth = 0;
        }
        b'|' if tracks_generic_angle_nesting(lang) && bytes.get(index + 1) == Some(&b'|') => {
            *angle_depth = 0;
        }
        _ => {}
    }
}

fn tracks_generic_angle_nesting(lang: LanguageKind) -> bool {
    matches!(lang, LanguageKind::Java | LanguageKind::Cpp | LanguageKind::CSharp)
}

fn looks_like_generic_open(bytes: &[u8], index: usize) -> bool {
    if bytes.get(index + 1).is_some_and(|byte| matches!(*byte, b'<' | b'='))
        || bytes.get(index.wrapping_sub(1)) == Some(&b'<')
    {
        return false;
    }
    let previous = bytes[..index]
        .iter()
        .rev()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace());
    let next = bytes[index + 1..]
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace());
    previous.is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b':' | b'>' | b')' | b']'))
        && next.is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b':' | b'(' | b'[' | b'?'))
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

fn extract_rust_file(src: &str, file: &mut ExtractedFile, guard: &mut AstWalkGuard) -> Result<(), ScanError> {
    crate::repo_scan_policy::check_deadline()?;
    crate::workspace_scan::validate_rust_syntax_complexity(src)?;
    crate::repo_scan_policy::charge_source_parse_work(src, "polyglot Rust parser work")?;
    let Ok(parsed) = syn::parse_file(src) else {
        return Ok(());
    };
    crate::repo_scan_policy::check_deadline()?;
    for item in &parsed.items {
        if crate::repo_scan_policy::check_deadline().is_err() {
            break;
        }
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
                visit_rust_use_paths(&u.tree, guard, &mut |parts| {
                    let module_bytes = parts
                        .iter()
                        .map(String::len)
                        .sum::<usize>()
                        .saturating_add(parts.len().saturating_sub(1).saturating_mul(2));
                    crate::repo_scan_policy::charge_generated_work(
                        1,
                        file.package_name
                            .len()
                            .saturating_add(file.rel_path.len())
                            .saturating_add(module_bytes.saturating_mul(2))
                            .saturating_add("use ;".len()),
                        "Rust use dependency intermediate",
                    )?;
                    let raw = parts.join("::");
                    file.deps.push(DepEdge {
                        from_crate: file.package_name.clone(),
                        from_file: file.rel_path.clone(),
                        to_module: raw.clone(),
                        raw: format!("use {raw};"),
                    });
                    Ok(())
                })?;
            }
            _ => {}
        }
    }
    Ok(())
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
    current_fn: Option<Arc<str>>,
    exported: bool,
    controller_prefix: Option<Arc<str>>,
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
    let Some(tree) = parse_with_scan_budget(&mut parser, src)? else {
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
                        current_fn: Some(Arc::from(name)),
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
                        current_fn: Some(Arc::from(name)),
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
                nest_controller_prefix(node, src)
                    .map(Arc::from)
                    .or(state.controller_prefix)
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
                file.push_dep(DepEdge {
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
                    file.push_call(CallSite {
                        name: name.clone(),
                        from_symbol: state.current_fn.as_deref().map(str::to_owned),
                    });
                }
                if options.v2_enabled && name == "require" {
                    if let Some(module) = first_arg_string(node, src) {
                        file.push_dep(DepEdge {
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
    let Some(tree) = parse_with_scan_budget(&mut parser, src)? else {
        return Ok(());
    };
    let bytes = src.as_bytes();
    if options.v3_enabled && file.rel_path.ends_with("urls.py") && !file.is_test_file {
        collect_django_urlpatterns(tree.root_node(), bytes, file, guard, 0);
    }
    walk_py_node(tree.root_node(), bytes, file, None, options, guard, 0);
    Ok(())
}

fn walk_py_node(
    node: Node<'_>,
    src: &[u8],
    file: &mut ExtractedFile,
    current_fn: Option<Arc<str>>,
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
                walk_py_children(node, src, file, Some(Arc::from(name)), options, guard, depth + 1);
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
                file.push_dep(DepEdge {
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
                    file.push_call(CallSite {
                        name,
                        from_symbol: current_fn.as_deref().map(str::to_owned),
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
    current_fn: Option<Arc<str>>,
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
    let Some(tree) = parse_with_scan_budget(&mut parser, src)? else {
        return Ok(());
    };
    let bytes = src.as_bytes();
    if let Some(package_name) = go_package_name(tree.root_node(), bytes, guard) {
        file.package_name = package_name;
        file.module_path = module_path(&file.package_name, &file.rel_path);
    }
    let group_prefixes = collect_go_group_prefixes(tree.root_node(), bytes, guard)?;
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
    current_fn: Option<Arc<str>>,
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
                        current_fn: Some(Arc::from(name)),
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
                        current_fn: Some(Arc::from(symbol_name)),
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
                    file.push_call(CallSite {
                        name,
                        from_symbol: state.current_fn.as_deref().map(str::to_owned),
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
    let Some(tree) = parse_with_scan_budget(&mut parser, src)? else {
        return Ok(());
    };
    let bytes = src.as_bytes();
    collect_spring_controllers(tree.root_node(), bytes, file, guard, 0);
    walk_java_node(tree.root_node(), bytes, file, guard, 0);
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
    let Some(tree) = parse_with_scan_budget(&mut parser, src)? else {
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

/// Django precision bar: only static calls inside a literal
/// `urlpatterns = [...]` in `urls.py` are admitted. Include targets must be a
/// string module with exactly one repo-local `<module path>.py` suffix match;
/// dynamic lists/import aliases are left unresolved rather than guessed.
fn collect_django_urlpatterns(
    node: Node<'_>,
    src: &[u8],
    file: &mut ExtractedFile,
    guard: &mut AstWalkGuard,
    depth: usize,
) {
    if !guard.allow_depth(depth) {
        return;
    }
    if node.kind() == "assignment" {
        let is_urlpatterns = node
            .child_by_field_name("left")
            .is_some_and(|left| node_text(left, src).trim() == "urlpatterns");
        if is_urlpatterns {
            if let Some(value) = node.child_by_field_name("right") {
                collect_django_pattern_list(value, src, file);
            }
            return;
        }
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_django_urlpatterns(child, src, file, guard, depth + 1);
    }
}

fn collect_django_pattern_list(value: Node<'_>, src: &[u8], file: &mut ExtractedFile) {
    if value.kind() != "list" {
        return;
    }
    let mut cursor = value.walk();
    for entry in value.named_children(&mut cursor) {
        if entry.kind() != "call" {
            continue;
        }
        let Some(function) = entry.child_by_field_name("function") else {
            continue;
        };
        if !matches!(last_ident_text(function, src).as_str(), "path" | "re_path" | "url") {
            continue;
        }
        let args = argument_nodes(entry);
        let positional: Vec<Node<'_>> = args
            .iter()
            .copied()
            .filter(|argument| argument.kind() != "keyword_argument")
            .collect();
        let (Some(path_node), Some(handler_node)) = (positional.first().copied(), positional.get(1).copied()) else {
            continue;
        };
        let Some(path) = string_literal_value(path_node, src, false) else {
            continue;
        };
        if handler_node.kind() == "call"
            && handler_node
                .child_by_field_name("function")
                .is_some_and(|include_fn| last_ident_text(include_fn, src) == "include")
        {
            let include_args = argument_nodes(handler_node);
            let Some(target_node) = include_args.first().copied() else {
                continue;
            };
            let target = string_literal_value(target_node, src, false).map_or_else(
                || DjangoIncludeTarget::Dynamic(node_text(target_node, src).trim().to_string()),
                DjangoIncludeTarget::Module,
            );
            file.push_django_include(DjangoIncludeCandidate {
                prefix: path,
                target,
                source_file: file.rel_path.clone(),
                source_line: entry.start_position().row + 1,
            });
            continue;
        }
        let handler = string_literal_value(handler_node, src, false)
            .unwrap_or_else(|| node_text(handler_node, src).trim().to_string());
        if handler.is_empty() {
            continue;
        }
        push_framework_route_candidate(
            file,
            "django",
            "ANY".to_string(),
            path,
            RouteHandler::Django(handler),
            entry.start_position().row + 1,
        );
    }
}

/// Spring precision bar: controller evidence is mandatory and only the
/// built-in mapping annotations with literal value/path strings are expanded.
/// Constants, meta/composed annotations and inherited mappings are not guessed.
fn collect_spring_controllers(
    node: Node<'_>,
    src: &[u8],
    file: &mut ExtractedFile,
    guard: &mut AstWalkGuard,
    depth: usize,
) {
    if file.is_test_file || !guard.allow_depth(depth) {
        return;
    }
    if node.kind() == "class_declaration" {
        collect_spring_controller(node, src, file);
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_spring_controllers(child, src, file, guard, depth + 1);
    }
}

fn collect_spring_controller(class: Node<'_>, src: &[u8], file: &mut ExtractedFile) {
    let annotations = java_annotations(class, src);
    if !annotations
        .iter()
        .any(|(raw, _)| matches!(spring_annotation_name(raw).as_str(), "RestController" | "Controller"))
    {
        return;
    }
    let Some(class_name) = field_ident(class, src, "name") else {
        return;
    };
    let class_paths = annotations
        .iter()
        .find(|(raw, _)| spring_annotation_name(raw) == "RequestMapping")
        .map_or_else(
            || SpringAnnotationPaths::Static(vec![String::new()]),
            |(raw, _)| spring_annotation_paths(raw),
        );
    let SpringAnnotationPaths::Static(class_paths) = class_paths else {
        return;
    };
    let Some(body) = class.child_by_field_name("body") else {
        return;
    };
    let mut cursor = body.walk();
    for method_node in body
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "method_declaration")
    {
        let Some(method_name) = field_ident(method_node, src, "name") else {
            continue;
        };
        for (annotation, line) in java_annotations(method_node, src) {
            let annotation_name = spring_annotation_name(&annotation);
            let methods = match annotation_name.as_str() {
                "GetMapping" => vec!["GET".to_string()],
                "PostMapping" => vec!["POST".to_string()],
                "PutMapping" => vec!["PUT".to_string()],
                "DeleteMapping" => vec!["DELETE".to_string()],
                "PatchMapping" => vec!["PATCH".to_string()],
                "RequestMapping" => spring_request_methods(&annotation),
                _ => continue,
            };
            let method_paths = match spring_annotation_paths(&annotation) {
                SpringAnnotationPaths::Static(paths) => paths,
                SpringAnnotationPaths::Dynamic => {
                    for http_method in &methods {
                        file.push_unresolved_route(UnresolvedRoute {
                            method: http_method.clone(),
                            path: class_paths.first().cloned().unwrap_or_default(),
                            handler_fn: format!("{class_name}.{method_name}"),
                            source_file: file.rel_path.clone(),
                            source_line: line,
                            reason: "annotation_dynamic".to_string(),
                        });
                    }
                    continue;
                }
            };
            for class_path in &class_paths {
                for method_path in &method_paths {
                    for http_method in &methods {
                        push_framework_route_candidate(
                            file,
                            "spring",
                            http_method.clone(),
                            join_spring_paths(class_path, method_path),
                            RouteHandler::Resolved {
                                name: format!("{class_name}.{method_name}"),
                                file: file.rel_path.clone(),
                                line: method_node.start_position().row + 1,
                            },
                            line,
                        );
                    }
                }
            }
        }
    }
}

fn java_annotations(node: Node<'_>, src: &[u8]) -> Vec<(String, usize)> {
    let mut out = Vec::new();
    let mut cursor = node.walk();
    let Some(modifiers) = node
        .named_children(&mut cursor)
        .find(|child| child.kind() == "modifiers")
    else {
        return out;
    };
    let mut modifier_cursor = modifiers.walk();
    for child in modifiers.named_children(&mut modifier_cursor) {
        if matches!(child.kind(), "annotation" | "marker_annotation") {
            out.push((node_text(child, src), child.start_position().row + 1));
        }
    }
    out
}

fn spring_annotation_name(raw: &str) -> String {
    raw.trim()
        .trim_start_matches('@')
        .split(['(', ' ', '\t', '\r', '\n'])
        .next()
        .unwrap_or_default()
        .rsplit('.')
        .next()
        .unwrap_or_default()
        .to_string()
}

fn spring_annotation_args(raw: &str) -> &str {
    raw.find('(')
        .and_then(|start| raw.rfind(')').map(|end| &raw[start + 1..end]))
        .unwrap_or_default()
}

enum SpringAnnotationPaths {
    Static(Vec<String>),
    Dynamic,
}

fn spring_annotation_paths(raw: &str) -> SpringAnnotationPaths {
    let args = spring_annotation_args(raw);
    if args.trim().is_empty() {
        return SpringAnnotationPaths::Static(vec![String::new()]);
    }
    let mut paths = Vec::new();
    let mut has_path_argument = false;
    for argument in split_top_level_args(args) {
        let (name, value) = argument
            .split_once('=')
            .map_or((None, argument), |(name, value)| (Some(name.trim()), value));
        if name.is_none() || matches!(name, Some("value" | "path")) {
            has_path_argument = true;
            paths.extend(all_literal_values(value));
        }
    }
    if paths.is_empty() {
        if has_path_argument {
            SpringAnnotationPaths::Dynamic
        } else {
            SpringAnnotationPaths::Static(vec![String::new()])
        }
    } else {
        SpringAnnotationPaths::Static(paths)
    }
}

fn spring_request_methods(raw: &str) -> Vec<String> {
    let args = spring_annotation_args(raw);
    let method_value = split_top_level_args(args).into_iter().find_map(|argument| {
        argument
            .split_once('=')
            .filter(|(name, _)| name.trim() == "method")
            .map(|(_, value)| value)
    });
    let Some(method_value) = method_value else {
        return vec!["ANY".to_string()];
    };
    let mut methods = Vec::new();
    for method in ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"] {
        if method_value
            .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
            .any(|token| token == method)
        {
            methods.push(method.to_string());
        }
    }
    if methods.is_empty() {
        vec!["ANY".to_string()]
    } else {
        methods
    }
}

fn split_top_level_args(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut depth = 0usize;
    let mut quote = None;
    let mut escaped = false;
    for (index, character) in text.char_indices() {
        if let Some(active_quote) = quote {
            if character == '\\' && !escaped {
                escaped = true;
                continue;
            }
            if character == active_quote && !escaped {
                quote = None;
            }
            escaped = false;
            continue;
        }
        match character {
            '"' | '\'' => quote = Some(character),
            '(' | '{' | '[' => depth += 1,
            ')' | '}' | ']' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                out.push(text[start..index].trim());
                start = index + 1;
            }
            _ => {}
        }
    }
    out.push(text[start..].trim());
    out
}

fn all_literal_values(text: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut remaining = text;
    while let Some(quote_index) = remaining.find(['"', '\'']) {
        let literal = &remaining[quote_index..];
        let Some(value) = literal_text_value(literal, false) else {
            break;
        };
        let consumed = value.len() + 2;
        values.push(value);
        if consumed >= literal.len() {
            break;
        }
        remaining = &literal[consumed..];
    }
    values
}

fn join_spring_paths(prefix: &str, path: &str) -> String {
    let joined = join_route_paths(prefix, path);
    if joined.is_empty() {
        "/".to_string()
    } else {
        joined
    }
}

#[derive(Debug, Clone, Default)]
struct CSharpWalkState {
    namespaces: Vec<String>,
    classes: Vec<String>,
    depth: usize,
}

fn extract_csharp_file(src: &str, file: &mut ExtractedFile, guard: &mut AstWalkGuard) -> Result<(), ScanError> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_c_sharp::LANGUAGE.into())
        .map_err(|err| ScanError::Io(std::io::Error::other(err.to_string())))?;
    let Some(tree) = parse_with_scan_budget(&mut parser, src)? else {
        return Ok(());
    };
    let root = tree.root_node();
    let mut state = CSharpWalkState::default();
    let mut cursor = root.walk();
    if let Some(namespace) = root
        .named_children(&mut cursor)
        .find(|child| child.kind() == "file_scoped_namespace_declaration")
        .and_then(|node| field_ident(node, src.as_bytes(), "name"))
    {
        state.namespaces = namespace.split('.').map(ToString::to_string).collect();
    }
    walk_csharp_node(root, src.as_bytes(), file, guard, state);
    Ok(())
}

fn walk_csharp_node(
    node: Node<'_>,
    src: &[u8],
    file: &mut ExtractedFile,
    guard: &mut AstWalkGuard,
    state: CSharpWalkState,
) {
    if !guard.allow_depth(state.depth) {
        return;
    }
    let mut child_state = state.clone();
    child_state.depth += 1;
    match node.kind() {
        "namespace_declaration" | "file_scoped_namespace_declaration" => {
            if let Some(name) = field_ident(node, src, "name") {
                child_state.namespaces = name.split('.').map(ToString::to_string).collect();
            }
        }
        "class_declaration" | "struct_declaration" | "record_declaration" | "interface_declaration" => {
            if let Some(name) = field_ident(node, src, "name") {
                let kind = if node.kind() == "interface_declaration" {
                    "interface"
                } else {
                    "class"
                };
                push_symbol(
                    file,
                    kind,
                    &name,
                    node.start_position().row + 1,
                    csharp_is_public(node, src),
                );
                if node.kind() == "class_declaration" && !file.is_test_file {
                    collect_aspnet_routes(node, src, file, &state.namespaces, &name);
                }
                child_state.classes.push(name);
            }
        }
        "enum_declaration" => {
            if let Some(name) = field_ident(node, src, "name") {
                push_symbol(
                    file,
                    "class",
                    &name,
                    node.start_position().row + 1,
                    csharp_is_public(node, src),
                );
            }
        }
        "method_declaration" => {
            if let Some(name) = field_ident(node, src, "name") {
                let qualified = qualify_parts(&state.namespaces, &state.classes, &name, ".");
                push_symbol(
                    file,
                    "method",
                    &qualified,
                    node.start_position().row + 1,
                    csharp_is_public(node, src),
                );
            }
        }
        "field_declaration" if csharp_is_const_field(node, src) => {
            if let Some(declaration) = direct_named_child(node, "variable_declaration") {
                let mut cursor = declaration.walk();
                for declarator in declaration.named_children(&mut cursor) {
                    if declarator.kind() == "variable_declarator" {
                        if let Some(name) = field_ident(declarator, src, "name") {
                            push_symbol(
                                file,
                                "const",
                                &name,
                                node.start_position().row + 1,
                                csharp_is_public(node, src),
                            );
                        }
                    }
                }
            }
        }
        "delegate_declaration" => {
            if let Some(name) = field_ident(node, src, "name") {
                push_symbol(
                    file,
                    "type",
                    &name,
                    node.start_position().row + 1,
                    csharp_is_public(node, src),
                );
            }
        }
        "using_directive" => {
            if node_text(node, src).contains('=') {
                if let Some(name) = field_ident(node, src, "name") {
                    push_symbol(file, "type", &name, node.start_position().row + 1, false);
                }
            }
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_csharp_node(child, src, file, guard, child_state.clone());
    }
}

fn csharp_modifier_words(node: Node<'_>, src: &[u8]) -> Vec<String> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| child.kind() == "modifier")
        .map(|child| node_text(child, src))
        .collect()
}

fn csharp_is_public(node: Node<'_>, src: &[u8]) -> bool {
    csharp_modifier_words(node, src).iter().any(|word| word == "public")
}

fn csharp_is_const_field(node: Node<'_>, src: &[u8]) -> bool {
    let modifiers = csharp_modifier_words(node, src);
    modifiers.iter().any(|word| word == "const")
        || (modifiers.iter().any(|word| word == "static") && modifiers.iter().any(|word| word == "readonly"))
}

#[derive(Debug, Clone)]
struct RubyWalkState {
    classes: Vec<String>,
    visibility: &'static str,
    in_method: bool,
    in_singleton_class: bool,
    depth: usize,
}

impl Default for RubyWalkState {
    fn default() -> Self {
        Self {
            classes: Vec::new(),
            visibility: "public",
            in_method: false,
            in_singleton_class: false,
            depth: 0,
        }
    }
}

fn extract_ruby_file(src: &str, file: &mut ExtractedFile, guard: &mut AstWalkGuard) -> Result<(), ScanError> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_ruby::LANGUAGE.into())
        .map_err(|err| ScanError::Io(std::io::Error::other(err.to_string())))?;
    let Some(tree) = parse_with_scan_budget(&mut parser, src)? else {
        return Ok(());
    };
    walk_ruby_node(tree.root_node(), src.as_bytes(), file, guard, RubyWalkState::default());
    if is_rails_routes_path(&file.rel_path) && !file.is_test_file {
        collect_rails_routes(src, file);
    }
    Ok(())
}

fn walk_ruby_node(
    node: Node<'_>,
    src: &[u8],
    file: &mut ExtractedFile,
    guard: &mut AstWalkGuard,
    state: RubyWalkState,
) {
    if !guard.allow_depth(state.depth) {
        return;
    }
    if node.kind() == "body_statement" || node.kind() == "program" {
        let mut sequence_state = state;
        sequence_state.depth += 1;
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if let Some(visibility) = ruby_visibility_marker(child, src) {
                sequence_state.visibility = visibility;
            } else {
                walk_ruby_node(child, src, file, guard, sequence_state.clone());
            }
        }
        return;
    }
    let mut child_state = state.clone();
    child_state.depth += 1;
    match node.kind() {
        "class" | "module" => {
            if let Some(name) = field_ident(node, src, "name") {
                let short_name = name.rsplit("::").next().unwrap_or(name.as_str()).to_string();
                push_symbol(file, "class", &short_name, node.start_position().row + 1, true);
                child_state.classes.extend(
                    name.split("::")
                        .filter(|part| !part.is_empty())
                        .map(ToString::to_string),
                );
                child_state.visibility = "public";
                child_state.in_singleton_class = false;
            }
        }
        "singleton_class" => {
            child_state.in_singleton_class = node
                .child_by_field_name("value")
                .is_some_and(|value| node_text(value, src).trim() == "self");
        }
        "method" => {
            if let Some(name) = field_ident(node, src, "name") {
                let qualified = if state.classes.is_empty() {
                    name
                } else if state.in_singleton_class {
                    format!("{}.{name}", state.classes.join("::"))
                } else {
                    format!("{}#{name}", state.classes.join("::"))
                };
                push_symbol(
                    file,
                    "method",
                    &qualified,
                    node.start_position().row + 1,
                    state.visibility == "public",
                );
                child_state.in_method = true;
            }
        }
        "singleton_method" => {
            if let Some(name) = field_ident(node, src, "name") {
                let receiver = node
                    .child_by_field_name("object")
                    .map_or_else(String::new, |object| node_text(object, src));
                let owner = if receiver == "self" && !state.classes.is_empty() {
                    state.classes.join("::")
                } else {
                    receiver
                };
                let qualified = if owner.is_empty() {
                    name
                } else {
                    format!("{owner}.{name}")
                };
                push_symbol(
                    file,
                    "method",
                    &qualified,
                    node.start_position().row + 1,
                    state.visibility == "public",
                );
                child_state.in_method = true;
            }
        }
        "assignment" if !state.in_method && !state.classes.is_empty() => {
            if let Some(left) = node.child_by_field_name("left") {
                if matches!(left.kind(), "constant" | "scope_resolution") {
                    let raw = node_text(left, src);
                    let name = raw.rsplit("::").next().unwrap_or(raw.as_str());
                    push_symbol(
                        file,
                        "const",
                        name,
                        node.start_position().row + 1,
                        state.visibility == "public",
                    );
                }
            }
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_ruby_node(child, src, file, guard, child_state.clone());
    }
}

fn ruby_visibility_marker(node: Node<'_>, src: &[u8]) -> Option<&'static str> {
    if node.kind() == "identifier" {
        return match node_text(node, src).as_str() {
            "public" => Some("public"),
            "private" => Some("private"),
            "protected" => Some("protected"),
            _ => None,
        };
    }
    if node.kind() != "call" || node.child_by_field_name("receiver").is_some() {
        return None;
    }
    let method = node
        .child_by_field_name("method")
        .map(|method| node_text(method, src))?;
    match method.as_str() {
        "public" => Some("public"),
        "private" => Some("private"),
        "protected" => Some("protected"),
        _ => None,
    }
}

#[derive(Debug, Clone, Default)]
struct SwiftWalkState {
    types: Vec<String>,
    in_function: bool,
    depth: usize,
}

fn extract_swift_file(src: &str, file: &mut ExtractedFile, guard: &mut AstWalkGuard) -> Result<(), ScanError> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_swift::LANGUAGE.into())
        .map_err(|err| ScanError::Io(std::io::Error::other(err.to_string())))?;
    let Some(tree) = parse_with_scan_budget(&mut parser, src)? else {
        return Ok(());
    };
    walk_swift_node(tree.root_node(), src.as_bytes(), file, guard, SwiftWalkState::default());
    Ok(())
}

fn walk_swift_node(
    node: Node<'_>,
    src: &[u8],
    file: &mut ExtractedFile,
    guard: &mut AstWalkGuard,
    state: SwiftWalkState,
) {
    if !guard.allow_depth(state.depth) {
        return;
    }
    let mut child_state = state.clone();
    child_state.depth += 1;
    match node.kind() {
        "class_declaration" => {
            let declaration_kind = node
                .child_by_field_name("declaration_kind")
                .map_or_else(String::new, |kind| node_text(kind, src));
            if let Some(name) = field_ident(node, src, "name") {
                if matches!(declaration_kind.as_str(), "class" | "struct" | "enum" | "actor") {
                    push_symbol(
                        file,
                        "class",
                        &name,
                        node.start_position().row + 1,
                        swift_is_public(node, src),
                    );
                }
                if declaration_kind != "enum" || !name.is_empty() {
                    child_state.types.push(name);
                }
            }
        }
        "protocol_declaration" => {
            if let Some(name) = field_ident(node, src, "name") {
                push_symbol(
                    file,
                    "interface",
                    &name,
                    node.start_position().row + 1,
                    swift_is_public(node, src),
                );
                child_state.types.push(name);
            }
        }
        "function_declaration" | "protocol_function_declaration" => {
            if let Some(name) = field_ident(node, src, "name") {
                let kind = if state.types.is_empty() { "fn" } else { "method" };
                push_symbol(
                    file,
                    kind,
                    &name,
                    node.start_position().row + 1,
                    swift_is_public(node, src),
                );
                child_state.in_function = true;
            }
        }
        "property_declaration" if !state.types.is_empty() && !state.in_function && swift_is_let(node, src) => {
            if let Some(pattern) = node.child_by_field_name("name") {
                if let Some(name) = first_source_identifier(&node_text(pattern, src)) {
                    push_symbol(
                        file,
                        "const",
                        &name,
                        node.start_position().row + 1,
                        swift_is_public(node, src),
                    );
                }
            }
        }
        "typealias_declaration" => {
            if let Some(name) = field_ident(node, src, "name") {
                push_symbol(
                    file,
                    "type",
                    &name,
                    node.start_position().row + 1,
                    swift_is_public(node, src),
                );
            }
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_swift_node(child, src, file, guard, child_state.clone());
    }
}

fn swift_is_public(node: Node<'_>, src: &[u8]) -> bool {
    let mut cursor = node.walk();
    let is_public = node
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "modifiers")
        .any(|modifiers| source_words(&node_text(modifiers, src)).any(|word| matches!(word, "public" | "open")));
    is_public
}

fn swift_is_let(node: Node<'_>, src: &[u8]) -> bool {
    let mut cursor = node.walk();
    let is_let = node
        .named_children(&mut cursor)
        .find(|child| child.kind() == "value_binding_pattern")
        .is_some_and(|binding| source_words(&node_text(binding, src)).any(|word| word == "let"));
    is_let
}

#[derive(Debug, Clone, Default)]
struct PhpWalkState {
    namespaces: Vec<String>,
    classes: Vec<String>,
    depth: usize,
}

fn extract_php_file(src: &str, file: &mut ExtractedFile, guard: &mut AstWalkGuard) -> Result<(), ScanError> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
        .map_err(|err| ScanError::Io(std::io::Error::other(err.to_string())))?;
    let Some(tree) = parse_with_scan_budget(&mut parser, src)? else {
        return Ok(());
    };
    let root = tree.root_node();
    let mut state = PhpWalkState::default();
    let mut cursor = root.walk();
    if let Some(namespace) = root
        .named_children(&mut cursor)
        .find(|child| child.kind() == "namespace_definition" && child.child_by_field_name("body").is_none())
        .and_then(|node| field_ident(node, src.as_bytes(), "name"))
    {
        state.namespaces = namespace
            .split('\\')
            .filter(|part| !part.is_empty())
            .map(ToString::to_string)
            .collect();
    }
    walk_php_node(root, src.as_bytes(), file, guard, state);
    if is_laravel_routes_path(&file.rel_path) && !file.is_test_file {
        collect_laravel_routes(src, file);
    }
    Ok(())
}

fn walk_php_node(node: Node<'_>, src: &[u8], file: &mut ExtractedFile, guard: &mut AstWalkGuard, state: PhpWalkState) {
    if !guard.allow_depth(state.depth) {
        return;
    }
    let mut child_state = state.clone();
    child_state.depth += 1;
    match node.kind() {
        "namespace_definition" => {
            if let Some(name) = field_ident(node, src, "name") {
                child_state.namespaces = name
                    .split('\\')
                    .filter(|part| !part.is_empty())
                    .map(ToString::to_string)
                    .collect();
            }
        }
        "class_declaration" | "trait_declaration" | "interface_declaration" => {
            if let Some(name) = field_ident(node, src, "name") {
                let kind = if node.kind() == "interface_declaration" {
                    "interface"
                } else {
                    "class"
                };
                push_symbol(file, kind, &name, node.start_position().row + 1, true);
                child_state.classes.push(name);
            }
        }
        "method_declaration" => {
            if let Some(name) = field_ident(node, src, "name") {
                let owner = qualify_parts(&state.namespaces, &state.classes, "", "\\");
                let qualified = if owner.is_empty() {
                    name
                } else {
                    format!("{owner}::{name}")
                };
                push_symbol(
                    file,
                    "method",
                    &qualified,
                    node.start_position().row + 1,
                    php_is_public(node, src),
                );
            }
        }
        "function_definition" => {
            if let Some(name) = field_ident(node, src, "name") {
                let qualified = qualify_parts(&state.namespaces, &[], &name, "\\");
                push_symbol(file, "fn", &qualified, node.start_position().row + 1, true);
            }
        }
        "const_declaration" => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if child.kind() == "const_element" {
                    let mut element_cursor = child.walk();
                    if let Some(name_node) = child
                        .named_children(&mut element_cursor)
                        .find(|element| element.kind() == "name")
                    {
                        push_symbol(
                            file,
                            "const",
                            &node_text(name_node, src),
                            node.start_position().row + 1,
                            php_is_public(node, src),
                        );
                    };
                }
            }
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_php_node(child, src, file, guard, child_state.clone());
    }
}

fn php_is_public(node: Node<'_>, src: &[u8]) -> bool {
    let mut cursor = node.walk();
    let visibility = node
        .named_children(&mut cursor)
        .find(|child| child.kind() == "visibility_modifier")
        .map(|modifier| node_text(modifier, src));
    !visibility
        .as_deref()
        .is_some_and(|modifier| matches!(modifier.trim(), "private" | "protected"))
}

fn direct_named_child<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
    let mut cursor = node.walk();
    let child = node.named_children(&mut cursor).find(|child| child.kind() == kind);
    child
}

fn qualify_parts(namespaces: &[String], types: &[String], name: &str, separator: &str) -> String {
    let mut parts = namespaces.to_vec();
    parts.extend(types.iter().cloned());
    if !name.is_empty() {
        parts.push(name.to_string());
    }
    parts.join(separator)
}

fn source_words(source: &str) -> impl Iterator<Item = &str> {
    source.split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
}

fn first_source_identifier(source: &str) -> Option<String> {
    source_words(source)
        .find(|word| !word.is_empty() && !matches!(*word, "let" | "var" | "static" | "class" | "public" | "private"))
        .map(ToString::to_string)
}

#[derive(Debug, Clone)]
struct CSharpAttribute {
    name: String,
    positional_string: Option<String>,
    has_positional_argument: bool,
}

fn collect_aspnet_routes(
    class_node: Node<'_>,
    src: &[u8],
    file: &mut ExtractedFile,
    namespaces: &[String],
    class_name: &str,
) {
    let attributes = csharp_attributes(class_node, src);
    let is_controller = attributes.iter().any(|attribute| attribute.name == "ApiController")
        || direct_named_child(class_node, "base_list").is_some_and(|base| {
            source_words(&node_text(base, src)).any(|word| matches!(word, "Controller" | "ControllerBase"))
        });
    if !is_controller {
        return;
    }
    let controller_token = class_name.strip_suffix("Controller").unwrap_or(class_name);
    let class_prefix = attributes
        .iter()
        .find(|attribute| attribute.name == "Route")
        .and_then(|attribute| attribute.positional_string.clone())
        .unwrap_or_default()
        .replace("[controller]", controller_token)
        .replace("[Controller]", controller_token);
    let Some(body) = class_node.child_by_field_name("body") else {
        return;
    };
    let mut cursor = body.walk();
    for method_node in body.named_children(&mut cursor) {
        if method_node.kind() != "method_declaration" {
            continue;
        }
        let Some(method_name) = field_ident(method_node, src, "name") else {
            continue;
        };
        let handler = qualify_parts(namespaces, &[class_name.to_string()], &method_name, ".");
        for attribute in csharp_attributes(method_node, src) {
            let method = match attribute.name.as_str() {
                "HttpGet" => Some("GET"),
                "HttpPost" => Some("POST"),
                "HttpPut" => Some("PUT"),
                "HttpPatch" => Some("PATCH"),
                "HttpDelete" => Some("DELETE"),
                "HttpHead" => Some("HEAD"),
                "HttpOptions" => Some("OPTIONS"),
                _ => None,
            };
            let Some(method) = method else {
                continue;
            };
            let Some(path) = attribute.positional_string else {
                if attribute.has_positional_argument {
                    push_unresolved_route(file, method, "<dynamic>", &handler, method_node, "dynamic");
                    continue;
                }
                push_framework_route_candidate(
                    file,
                    "aspnet",
                    method.to_string(),
                    join_route_paths(&class_prefix, ""),
                    RouteHandler::Named(handler.clone()),
                    method_node.start_position().row + 1,
                );
                continue;
            };
            let path = aspnet_route_path(&class_prefix, &path, controller_token, &method_name);
            push_framework_route_candidate(
                file,
                "aspnet",
                method.to_string(),
                path,
                RouteHandler::Named(handler.clone()),
                method_node.start_position().row + 1,
            );
        }
    }
}

fn aspnet_route_path(class_prefix: &str, method_template: &str, controller: &str, action: &str) -> String {
    let substitute_tokens = |value: &str| {
        value
            .replace("[controller]", controller)
            .replace("[Controller]", controller)
            .replace("[action]", action)
            .replace("[Action]", action)
        // `[area]` needs controller-model metadata that this file-local
        // detector does not have, so it is deliberately left unresolved.
    };
    let template = substitute_tokens(method_template);
    if let Some(absolute) = template.strip_prefix("~/") {
        return join_route_paths("", absolute);
    }
    if template.starts_with('/') {
        return join_route_paths("", &template);
    }
    join_route_paths(&substitute_tokens(class_prefix), &template)
}

fn csharp_attributes(node: Node<'_>, src: &[u8]) -> Vec<CSharpAttribute> {
    let mut attributes = Vec::new();
    let mut cursor = node.walk();
    for list in node
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "attribute_list")
    {
        let mut list_cursor = list.walk();
        for attribute in list
            .named_children(&mut list_cursor)
            .filter(|child| child.kind() == "attribute")
        {
            let Some(mut name) = field_ident(attribute, src, "name") else {
                continue;
            };
            if let Some(short) = name.rsplit('.').next() {
                name = short.trim_end_matches("Attribute").to_string();
            }
            let mut positional_string = None;
            let mut has_positional_argument = false;
            if let Some(arguments) = direct_named_child(attribute, "attribute_argument_list") {
                let mut argument_cursor = arguments.walk();
                for argument in arguments
                    .named_children(&mut argument_cursor)
                    .filter(|argument| argument.kind() == "attribute_argument")
                {
                    if argument.child_by_field_name("name").is_some() {
                        continue;
                    }
                    has_positional_argument = true;
                    let mut value_cursor = argument.walk();
                    positional_string = argument
                        .named_children(&mut value_cursor)
                        .next()
                        .and_then(|value| csharp_string_literal_value(value, src, 0));
                    break;
                }
            }
            attributes.push(CSharpAttribute {
                name,
                positional_string,
                has_positional_argument,
            });
        }
    }
    attributes
}

fn csharp_string_literal_value(node: Node<'_>, src: &[u8], depth: usize) -> Option<String> {
    if depth > 8 {
        return None;
    }
    let text = node_text(node, src);
    match node.kind() {
        "string_literal" => literal_text_value(&text, false),
        "verbatim_string_literal" => text
            .strip_prefix('@')
            .and_then(|literal| literal_text_value(literal, false)),
        "interpolated_string_expression" | "raw_string_literal" => None,
        _ => {
            let mut cursor = node.walk();
            let value = node
                .named_children(&mut cursor)
                .find_map(|child| csharp_string_literal_value(child, src, depth + 1));
            value
        }
    }
}

fn is_rails_routes_path(path: &str) -> bool {
    path == "config/routes.rb" || path.ends_with("/config/routes.rb")
}

#[derive(Debug, Clone)]
struct RailsRouteFrame {
    path_prefix: String,
    controller_prefix: Option<String>,
    conditional: bool,
}

fn collect_rails_routes(src: &str, file: &mut ExtractedFile) {
    let mut frames: Vec<RailsRouteFrame> = Vec::new();
    for (line_index, raw_line) in src.lines().enumerate() {
        let line = strip_hash_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        if line == "end" || line.starts_with("end ") {
            frames.pop();
            continue;
        }
        if let Some(namespace) = rails_symbol_argument(line, "namespace") {
            frames.push(RailsRouteFrame {
                path_prefix: namespace.clone(),
                controller_prefix: Some(namespace),
                conditional: false,
            });
            continue;
        }
        if line.starts_with("scope") && line.ends_with(" do") {
            frames.push(RailsRouteFrame {
                path_prefix: rails_scope_path(line).unwrap_or_default(),
                controller_prefix: rails_option_value(line, "module"),
                conditional: false,
            });
            continue;
        }
        let conditional =
            frames.iter().any(|frame| frame.conditional) || line.contains(" if ") || line.contains(" unless ");
        let prefix = frames
            .iter()
            .map(|frame| frame.path_prefix.as_str())
            .fold(String::new(), |joined, component| join_route_paths(&joined, component));
        let controller_namespace = frames
            .iter()
            .filter_map(|frame| frame.controller_prefix.as_deref())
            .filter(|component| !component.is_empty())
            .collect::<Vec<_>>()
            .join("/");
        let resources = rails_resource_names(line);
        if !resources.is_empty() {
            if conditional {
                for resource in resources {
                    push_unresolved_route_at(
                        file,
                        "ANY",
                        &join_route_paths(&prefix, &resource),
                        "resources",
                        line_index + 1,
                        "dynamic",
                    );
                }
            } else {
                let actions = rails_resource_actions(line);
                for resource in resources {
                    let handler_owner = if controller_namespace.is_empty() {
                        resource.clone()
                    } else {
                        format!("{controller_namespace}/{resource}")
                    };
                    push_resource_routes(
                        file,
                        &prefix,
                        &resource,
                        &handler_owner,
                        line_index + 1,
                        ResourceStyle::Rails,
                        Some(&actions),
                    );
                }
            }
        } else if let Some((method, rest)) = rails_route_method(line) {
            let literals = quoted_literals(rest);
            let path_is_literal = rest
                .trim_start()
                .trim_start_matches('(')
                .trim_start()
                .starts_with(['\'', '"']);
            let path = path_is_literal.then(|| literals.first().cloned()).flatten();
            let handler = if path_is_literal {
                literals.get(1).cloned()
            } else {
                literals.first().cloned()
            }
            .map(|handler| {
                if controller_namespace.is_empty() {
                    handler
                } else {
                    format!("{controller_namespace}/{handler}")
                }
            });
            match (path, handler, conditional) {
                (Some(path), Some(handler), false) => push_framework_route_candidate(
                    file,
                    "rails",
                    method.to_string(),
                    join_route_paths(&prefix, &path),
                    RouteHandler::Named(handler),
                    line_index + 1,
                ),
                (path, handler, _) => push_unresolved_route_at(
                    file,
                    method,
                    &path.map_or_else(|| "<dynamic>".to_string(), |path| join_route_paths(&prefix, &path)),
                    handler.as_deref().unwrap_or("<dynamic>"),
                    line_index + 1,
                    "dynamic",
                ),
            }
        }
        if line.ends_with(" do") {
            let is_conditional = line.starts_with("if ")
                || line.starts_with("unless ")
                || line.starts_with("case ")
                || line.starts_with("while ");
            frames.push(RailsRouteFrame {
                path_prefix: String::new(),
                controller_prefix: None,
                conditional: is_conditional,
            });
        }
    }
}

fn rails_scope_path(line: &str) -> Option<String> {
    let rest = line
        .strip_prefix("scope")?
        .trim_start()
        .trim_start_matches('(')
        .trim_start();
    if rest.starts_with(['\'', '"']) {
        return quoted_literals(rest).into_iter().next();
    }
    rails_option_value(line, "path")
}

fn rails_option_value(line: &str, option: &str) -> Option<String> {
    let marker = format!("{option}:");
    let value = line.split_once(&marker)?.1.trim_start();
    if value.starts_with(['\'', '"']) {
        return quoted_literals(value).into_iter().next();
    }
    let symbol = value.strip_prefix(':')?;
    let value: String = symbol
        .chars()
        .take_while(|character| character.is_ascii_alphanumeric() || matches!(*character, '_' | '-'))
        .collect();
    (!value.is_empty()).then_some(value)
}

fn rails_resource_names(line: &str) -> Vec<String> {
    let Some(rest) = line.strip_prefix("resources") else {
        return Vec::new();
    };
    if !(rest.starts_with(char::is_whitespace) || rest.starts_with('(')) {
        return Vec::new();
    }
    let option_start = ["only:", "except:", "path:", "controller:", "as:", "param:"]
        .iter()
        .filter_map(|option| rest.find(option))
        .min()
        .unwrap_or(rest.len());
    ruby_static_literals(&rest[..option_start])
}

fn rails_resource_actions(line: &str) -> HashSet<String> {
    let all: HashSet<String> = ["index", "show", "new", "create", "edit", "update", "destroy"]
        .into_iter()
        .map(ToString::to_string)
        .collect();
    if let Some(only) = rails_option_symbols(line, "only") {
        return only.into_iter().filter(|action| all.contains(action)).collect();
    }
    if let Some(except) = rails_option_symbols(line, "except") {
        return all.difference(&except).cloned().collect();
    }
    all
}

fn rails_option_symbols(line: &str, option: &str) -> Option<HashSet<String>> {
    let marker = format!("{option}:");
    let after = line.split_once(&marker)?.1.trim_start();
    let value = if let Some(array) = after.strip_prefix('[') {
        array.split_once(']').map_or(array, |(value, _)| value)
    } else {
        after.split_once(',').map_or(after, |(value, _)| value)
    };
    Some(ruby_static_literals(value).into_iter().collect())
}

fn ruby_static_literals(source: &str) -> Vec<String> {
    let bytes = source.as_bytes();
    let mut values = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        if matches!(bytes[index], b'\'' | b'"') {
            let quote = bytes[index];
            let body_start = index + 1;
            let Some(end) = find_closing_quote(&source[body_start..], quote) else {
                break;
            };
            values.push(source[body_start..body_start + end].to_string());
            index = body_start + end + 1;
            continue;
        }
        if bytes[index] == b':' && bytes.get(index.wrapping_sub(1)) != Some(&b':') {
            let start = index + 1;
            let mut end = start;
            while bytes
                .get(end)
                .is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-'))
            {
                end += 1;
            }
            if end > start {
                values.push(source[start..end].to_string());
                index = end;
                continue;
            }
        }
        index += 1;
    }
    values
}

fn rails_route_method(line: &str) -> Option<(&'static str, &str)> {
    for (name, method) in [
        ("get", "GET"),
        ("post", "POST"),
        ("put", "PUT"),
        ("patch", "PATCH"),
        ("delete", "DELETE"),
    ] {
        if let Some(rest) = line.strip_prefix(name) {
            if rest.starts_with(char::is_whitespace) || rest.starts_with('(') {
                return Some((method, rest));
            }
        }
    }
    None
}

fn rails_symbol_argument(line: &str, call: &str) -> Option<String> {
    let rest = line.strip_prefix(call)?;
    if !(rest.starts_with(char::is_whitespace) || rest.starts_with('(')) {
        return None;
    }
    if let Some(quoted) = quoted_literals(rest).first() {
        return Some(quoted.clone());
    }
    let colon = rest.find(':')? + 1;
    let symbol: String = rest[colon..]
        .chars()
        .take_while(|character| character.is_ascii_alphanumeric() || matches!(*character, '_' | '-'))
        .collect();
    (!symbol.is_empty()).then_some(symbol)
}

fn is_laravel_routes_path(path: &str) -> bool {
    Path::new(path)
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("php"))
        && (path.starts_with("routes/") || path.contains("/routes/"))
}

#[derive(Debug, Clone)]
struct LaravelGroupFrame {
    prefix: String,
    body_depth: usize,
}

fn collect_laravel_routes(src: &str, file: &mut ExtractedFile) {
    let mut groups: Vec<LaravelGroupFrame> = Vec::new();
    let mut brace_depth = 0usize;
    for (line_index, raw_line) in src.lines().enumerate() {
        let line = strip_php_line_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        let brace_delta = source_brace_delta(line);
        if let Some(prefix) = laravel_group_prefix(line) {
            let body_depth = if brace_delta > 0 {
                brace_depth.saturating_add(brace_delta as usize)
            } else {
                brace_depth.saturating_add(1)
            };
            groups.push(LaravelGroupFrame { prefix, body_depth });
            brace_depth = apply_brace_delta(brace_depth, brace_delta);
            while groups.last().is_some_and(|group| group.body_depth > brace_depth) {
                groups.pop();
            }
            continue;
        }
        let prefix = groups
            .iter()
            .map(|group| group.prefix.as_str())
            .fold(String::new(), |joined, component| join_route_paths(&joined, component));
        let resource = line
            .strip_prefix("Route::apiResource")
            .map(|rest| (rest, ResourceStyle::LaravelApi))
            .or_else(|| {
                line.strip_prefix("Route::resource")
                    .map(|rest| (rest, ResourceStyle::Laravel))
            });
        if let Some((rest, style)) = resource {
            let Some((resource, controller)) = laravel_resource_arguments(rest) else {
                push_unresolved_route_at(file, "ANY", "<dynamic>", "<dynamic>", line_index + 1, "dynamic");
                brace_depth = apply_brace_delta(brace_depth, brace_delta);
                continue;
            };
            push_resource_routes(file, &prefix, &resource, &controller, line_index + 1, style, None);
            brace_depth = apply_brace_delta(brace_depth, brace_delta);
            while groups.last().is_some_and(|group| group.body_depth > brace_depth) {
                groups.pop();
            }
            continue;
        }
        if let Some((method, rest)) = laravel_route_method(line) {
            let arguments = laravel_call_arguments(rest);
            let path = arguments
                .first()
                .and_then(|argument| literal_text_value(argument, false));
            let handler = arguments.get(1).and_then(|argument| laravel_handler(argument));
            match (path, handler) {
                (Some(path), Some(handler)) => push_framework_route_candidate(
                    file,
                    "laravel",
                    method.to_string(),
                    join_route_paths(&prefix, &path),
                    RouteHandler::Named(handler),
                    line_index + 1,
                ),
                (path, handler) => push_unresolved_route_at(
                    file,
                    method,
                    &path.map_or_else(|| "<dynamic>".to_string(), |path| join_route_paths(&prefix, &path)),
                    handler.as_deref().unwrap_or("<dynamic>"),
                    line_index + 1,
                    "dynamic",
                ),
            }
        }
        brace_depth = apply_brace_delta(brace_depth, brace_delta);
        while groups.last().is_some_and(|group| group.body_depth > brace_depth) {
            groups.pop();
        }
    }
}

fn laravel_group_prefix(line: &str) -> Option<String> {
    let is_array_group = line.starts_with("Route::group") && line.contains('(');
    let is_fluent_group = line
        .find("->group")
        .and_then(|index| line.get(index + "->group".len()..))
        .is_some_and(|tail| tail.trim_start().starts_with('('));
    if !is_array_group && !is_fluent_group {
        return None;
    }
    if is_array_group {
        let literals = quoted_literals(line);
        return Some(
            literals
                .iter()
                .position(|literal| literal == "prefix")
                .and_then(|index| literals.get(index + 1))
                .cloned()
                .unwrap_or_default(),
        );
    }
    Some(laravel_fluent_prefix(line).unwrap_or_default())
}

fn laravel_fluent_prefix(line: &str) -> Option<String> {
    let marker = "prefix";
    let mut search_from = 0usize;
    while let Some(relative) = line[search_from..].find(marker) {
        let start = search_from + relative + marker.len();
        let tail = line.get(start..)?.trim_start();
        if tail.starts_with('(') {
            return quoted_literals(tail).into_iter().next();
        }
        search_from = start;
    }
    None
}

fn laravel_resource_arguments(source: &str) -> Option<(String, String)> {
    let arguments = laravel_call_arguments(source);
    let resource = arguments
        .first()
        .and_then(|argument| literal_text_value(argument, false))?;
    let controller = arguments.get(1).and_then(|argument| php_class_literal(argument))?;
    Some((resource, controller))
}

fn laravel_handler(argument: &str) -> Option<String> {
    let handler = argument.trim_start();
    let handler = handler.strip_prefix("static ").unwrap_or(handler).trim_start();
    if handler.starts_with("function") || handler.starts_with("fn ") || handler.starts_with("fn(") {
        Some("closure".to_string())
    } else {
        laravel_array_handler(handler)
    }
}

fn laravel_call_arguments(source: &str) -> Vec<String> {
    let Some(open) = source.find('(') else {
        return Vec::new();
    };
    let mut arguments = Vec::new();
    let mut start = open + 1;
    let mut paren_depth = 1usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;
    let mut quote = None;
    let mut escaped = false;
    for (relative, character) in source[open + 1..].char_indices() {
        let index = open + 1 + relative;
        if let Some(active_quote) = quote {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == active_quote {
                quote = None;
            }
            continue;
        }
        if matches!(character, '\'' | '"') {
            quote = Some(character);
            continue;
        }
        match character {
            '(' => paren_depth += 1,
            ')' => {
                paren_depth = paren_depth.saturating_sub(1);
                if paren_depth == 0 {
                    arguments.push(source[start..index].trim().to_string());
                    return arguments;
                }
            }
            '[' => bracket_depth += 1,
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            '{' => brace_depth += 1,
            '}' => brace_depth = brace_depth.saturating_sub(1),
            ',' if paren_depth == 1 && bracket_depth == 0 && brace_depth == 0 => {
                arguments.push(source[start..index].trim().to_string());
                start = index + 1;
            }
            _ => {}
        }
    }
    if start < source.len() {
        arguments.push(source[start..].trim().to_string());
    }
    arguments
}

fn source_brace_delta(source: &str) -> isize {
    let mut delta = 0isize;
    let mut quote = None;
    let mut escaped = false;
    for character in source.chars() {
        if let Some(active_quote) = quote {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == active_quote {
                quote = None;
            }
        } else if matches!(character, '\'' | '"') {
            quote = Some(character);
        } else if character == '{' {
            delta += 1;
        } else if character == '}' {
            delta -= 1;
        }
    }
    delta
}

fn apply_brace_delta(depth: usize, delta: isize) -> usize {
    if delta >= 0 {
        depth.saturating_add(delta as usize)
    } else {
        depth.saturating_sub(delta.unsigned_abs())
    }
}

fn laravel_array_handler(source: &str) -> Option<String> {
    let array_start = source.find('[')?;
    let array_end = source[array_start + 1..].find(']')? + array_start + 1;
    let array = &source[array_start + 1..array_end];
    let class = php_class_literal(array)?;
    let method = quoted_literals(array).into_iter().next()?;
    Some(format!("{class}::{method}"))
}

fn laravel_route_method(line: &str) -> Option<(&'static str, &str)> {
    for (name, method) in [
        ("get", "GET"),
        ("post", "POST"),
        ("put", "PUT"),
        ("patch", "PATCH"),
        ("delete", "DELETE"),
    ] {
        if let Some(rest) = line.strip_prefix(&format!("Route::{name}")) {
            if rest.trim_start().starts_with('(') {
                return Some((method, rest));
            }
        }
    }
    None
}

fn php_class_literal(source: &str) -> Option<String> {
    let before = source.split_once("::class")?.0;
    let class: String = before
        .chars()
        .rev()
        .take_while(|character| character.is_ascii_alphanumeric() || matches!(*character, '_' | '\\'))
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    (!class.is_empty()).then_some(class)
}

#[derive(Debug, Clone, Copy)]
enum ResourceStyle {
    Rails,
    Laravel,
    LaravelApi,
}

fn push_resource_routes(
    file: &mut ExtractedFile,
    prefix: &str,
    resource: &str,
    handler_owner: &str,
    source_line: usize,
    style: ResourceStyle,
    allowed_actions: Option<&HashSet<String>>,
) {
    let base = join_route_paths(prefix, resource);
    let singular = resource.trim_end_matches('s');
    let parameter = match style {
        ResourceStyle::Rails => ":id".to_string(),
        ResourceStyle::Laravel | ResourceStyle::LaravelApi => format!("{{{singular}}}"),
    };
    let separator = match style {
        ResourceStyle::Rails => "#",
        ResourceStyle::Laravel | ResourceStyle::LaravelApi => "::",
    };
    let framework = match style {
        ResourceStyle::Rails => "rails",
        ResourceStyle::Laravel | ResourceStyle::LaravelApi => "laravel",
    };
    let actions: Vec<(&str, String, &str)> = match style {
        ResourceStyle::Rails => vec![
            ("GET", base.clone(), "index"),
            ("GET", format!("{base}/{parameter}"), "show"),
            ("GET", format!("{base}/new"), "new"),
            ("POST", base.clone(), "create"),
            ("GET", format!("{base}/{parameter}/edit"), "edit"),
            ("PATCH", format!("{base}/{parameter}"), "update"),
            ("DELETE", format!("{base}/{parameter}"), "destroy"),
        ],
        ResourceStyle::Laravel => vec![
            ("GET", base.clone(), "index"),
            ("GET", format!("{base}/create"), "create"),
            ("POST", base.clone(), "store"),
            ("GET", format!("{base}/{parameter}"), "show"),
            ("GET", format!("{base}/{parameter}/edit"), "edit"),
            ("PUT", format!("{base}/{parameter}"), "update"),
            ("DELETE", format!("{base}/{parameter}"), "destroy"),
        ],
        ResourceStyle::LaravelApi => vec![
            ("GET", base.clone(), "index"),
            ("POST", base.clone(), "store"),
            ("GET", format!("{base}/{parameter}"), "show"),
            ("PUT", format!("{base}/{parameter}"), "update"),
            ("DELETE", format!("{base}/{parameter}"), "destroy"),
        ],
    };
    for (method, path, action) in actions {
        if allowed_actions.is_some_and(|allowed| !allowed.contains(action)) {
            continue;
        }
        push_framework_route_candidate(
            file,
            framework,
            method.to_string(),
            path,
            RouteHandler::Named(format!("{handler_owner}{separator}{action}")),
            source_line,
        );
    }
}

fn push_unresolved_route(
    file: &mut ExtractedFile,
    method: &str,
    path: &str,
    handler: &str,
    node: Node<'_>,
    reason: &str,
) {
    push_unresolved_route_at(file, method, path, handler, node.start_position().row + 1, reason);
}

fn push_unresolved_route_at(
    file: &mut ExtractedFile,
    method: &str,
    path: &str,
    handler: &str,
    source_line: usize,
    reason: &str,
) {
    file.push_unresolved_route(UnresolvedRoute {
        method: method.to_string(),
        path: path.to_string(),
        handler_fn: handler.to_string(),
        source_file: file.rel_path.clone(),
        source_line,
        reason: reason.to_string(),
    });
}

fn quoted_literals(source: &str) -> Vec<String> {
    let bytes = source.as_bytes();
    let mut literals = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        let quote = bytes[index];
        if !matches!(quote, b'\'' | b'"') {
            index += 1;
            continue;
        }
        let body_start = index + 1;
        let Some(end) = find_closing_quote(&source[body_start..], quote) else {
            break;
        };
        literals.push(source[body_start..body_start + end].to_string());
        index = body_start + end + 1;
    }
    literals
}

fn strip_hash_comment(line: &str) -> &str {
    strip_line_comment_outside_quotes(line, '#')
}

fn strip_php_line_comment(line: &str) -> &str {
    let hash_stripped = strip_line_comment_outside_quotes(line, '#');
    strip_double_slash_comment(hash_stripped)
}

fn strip_line_comment_outside_quotes(line: &str, marker: char) -> &str {
    let mut quote = None;
    let mut escaped = false;
    for (index, character) in line.char_indices() {
        if let Some(active_quote) = quote {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == active_quote {
                quote = None;
            }
        } else if matches!(character, '\'' | '"') {
            quote = Some(character);
        } else if character == marker {
            return &line[..index];
        }
    }
    line
}

fn strip_double_slash_comment(line: &str) -> &str {
    let mut quote = None;
    let mut escaped = false;
    let mut chars = line.char_indices().peekable();
    while let Some((index, character)) = chars.next() {
        if let Some(active_quote) = quote {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == active_quote {
                quote = None;
            }
        } else if matches!(character, '\'' | '"') {
            quote = Some(character);
        } else if character == '/' && chars.peek().is_some_and(|(_, next)| *next == '/') {
            return &line[..index];
        }
    }
    line
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
        let Some((path, methods)) = parse_python_route_decorator(decorator, src, guard, depth + 1) else {
            continue;
        };
        let handler = RouteHandler::Named(handler_name.clone());
        for method in methods {
            push_route_candidate_borrowed(file, &method, &path, &handler, decorator.start_position().row + 1);
        }
    }
}

fn parse_python_route_decorator(
    decorator: Node<'_>,
    src: &[u8],
    guard: &mut AstWalkGuard,
    depth: usize,
) -> Option<(String, Vec<String>)> {
    let call = first_node_by_kind(decorator, "call", guard, depth + 1)?;
    let function = call.child_by_field_name("function")?;
    let method_name = last_ident_text(function, src);
    let method_lower = method_name.to_ascii_lowercase();
    let args = argument_nodes(call);
    let path = python_route_path_from_args(&args, src)?;
    if !path.starts_with('/') {
        return None;
    }
    let methods = match method_lower.as_str() {
        "get" | "post" | "put" | "delete" | "patch" | "head" | "options" => {
            vec![method_lower.to_ascii_uppercase()]
        }
        "websocket" => vec!["WS".to_string()],
        "route" => python_route_methods(&args, src, &["GET"]),
        _ => return None,
    };
    Some((path, methods))
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
        push_route_candidate_borrowed(file, &method, &path, &handler, node.start_position().row + 1);
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
    default_methods
        .iter()
        .filter_map(|method| {
            crate::repo_scan_policy::charge_generated_work(1, method.len(), "Python route-method intermediate")
                .ok()
                .map(|()| (*method).to_string())
        })
        .collect()
}

fn python_methods_list(value: Node<'_>, src: &[u8]) -> Option<Vec<String>> {
    if value.kind() != "list" {
        return None;
    }
    let mut methods = Vec::new();
    let mut cursor = value.walk();
    for child in value.named_children(&mut cursor) {
        let method = string_literal_value(child, src, false)?;
        if crate::repo_scan_policy::charge_generated_work(1, method.len(), "Python route-method intermediate").is_err()
        {
            return None;
        }
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
                let Some(prefix) = go_group_call_prefix(operand, src, group_prefixes, guard, depth + 1)
                    .ok()
                    .flatten()
                else {
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

fn collect_go_group_prefixes(
    root: Node<'_>,
    src: &[u8],
    guard: &mut AstWalkGuard,
) -> Result<HashMap<String, String>, ScanError> {
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
            if let Some(prefix) = go_group_call_prefix(*call, src, &prefixes, guard, 0)? {
                crate::repo_scan_policy::charge_generated_work(
                    1,
                    name.len().saturating_add(prefix.len()),
                    "Go route-group prefix index",
                )?;
                prefixes.insert(name.clone(), prefix);
                changed = true;
            }
        }
    }
    Ok(prefixes)
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
            if crate::repo_scan_policy::charge_generated_work(
                1,
                name.len().saturating_add(std::mem::size_of::<Node<'a>>()),
                "Go route-group assignment index",
            )
            .is_ok()
            {
                out.push((name, call));
            }
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
) -> Result<Option<String>, ScanError> {
    if !guard.allow_depth(depth) {
        return Ok(None);
    }
    if call.kind() != "call_expression" {
        return Ok(None);
    }
    let Some(function) = call.child_by_field_name("function") else {
        return Ok(None);
    };
    if function.kind() != "selector_expression" || go_selector_field(function, src).as_deref() != Some("Group") {
        return Ok(None);
    }
    let Some(object) = function.child_by_field_name("operand") else {
        return Ok(None);
    };
    let base_prefix = match object.kind() {
        "identifier" => {
            let receiver = node_text(object, src);
            if let Some(prefix) = group_prefixes.get(&receiver) {
                crate::repo_scan_policy::charge_generated_work(1, prefix.len(), "Go route-group prefix intermediate")?;
                prefix.clone()
            } else if go_route_receiver_allowed(&receiver) {
                String::new()
            } else {
                return Ok(None);
            }
        }
        "call_expression" => {
            let Some(prefix) = go_group_call_prefix(object, src, group_prefixes, guard, depth + 1)? else {
                return Ok(None);
            };
            prefix
        }
        _ => return Ok(None),
    };
    let args = argument_nodes(call);
    let Some(path) = args
        .first()
        .copied()
        .and_then(|arg| string_literal_value(arg, src, true))
    else {
        return Ok(None);
    };
    if !path.starts_with('/') {
        return Ok(None);
    }
    crate::repo_scan_policy::charge_generated_work(
        1,
        base_prefix.len().saturating_add(path.len()).saturating_add(1),
        "Go route-group joined prefix",
    )?;
    Ok(Some(join_route_paths(&base_prefix, &path)))
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
        file.push_dep(DepEdge {
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
            return bounded_package_name(&node_text(child, src));
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
    file.push_route(RouteCandidate {
        method,
        path,
        handler,
        framework: None,
        source_file: file.rel_path.clone(),
        source_line,
    });
}

fn push_route_candidate_borrowed(
    file: &mut ExtractedFile,
    method: &str,
    path: &str,
    handler: &RouteHandler,
    source_line: usize,
) {
    let handler_bytes = match handler {
        RouteHandler::Inline => 0,
        RouteHandler::Named(name) | RouteHandler::Django(name) => name.len(),
        RouteHandler::Resolved { name, file, .. } => name.len().saturating_add(file.len()),
    };
    let bytes = method
        .len()
        .saturating_add(path.len())
        .saturating_add(file.rel_path.len())
        .saturating_add(handler_bytes);
    if crate::repo_scan_policy::charge_generated_work(1, bytes, "polyglot route intermediate").is_err() {
        return;
    }
    file.routes.push(RouteCandidate {
        method: method.to_string(),
        path: path.to_string(),
        handler: handler.clone(),
        framework: None,
        source_file: file.rel_path.clone(),
        source_line,
    });
}

fn push_framework_route_candidate(
    file: &mut ExtractedFile,
    framework: &str,
    method: String,
    path: String,
    handler: RouteHandler,
    source_line: usize,
) {
    file.push_route(RouteCandidate {
        method,
        path,
        handler,
        framework: Some(framework.to_string()),
        source_file: file.rel_path.clone(),
        source_line,
    });
}

fn push_local_binding(file: &mut ExtractedFile, name: &str, line: usize) {
    if name.is_empty() || file.local_bindings.contains_key(name) {
        return;
    }
    if crate::repo_scan_policy::charge_generated_work(1, name.len(), "polyglot local-binding index").is_err() {
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
    (end_idx <= crate::workspace_scan::SCAN_METADATA_MAX_BYTES).then(|| body[..end_idx].to_string())
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
        if crate::repo_scan_policy::charge_generated_work(
            1,
            body_end.saturating_sub(body_start),
            "Vue script-block intermediate",
        )
        .is_err()
        {
            break;
        }
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
    let generated_bytes = file
        .package_name
        .len()
        .saturating_add(file.module_path.len())
        .saturating_add(file.rel_path.len())
        .saturating_add(kind.len())
        .saturating_add(name.len());
    if crate::repo_scan_policy::charge_generated_work(
        2,
        generated_bytes.saturating_mul(2),
        "polyglot symbol and dedup index",
    )
    .is_err()
    {
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
) -> Result<(), ScanError> {
    for (file_index, file) in extracted.iter().enumerate() {
        if file_index % 256 == 0 {
            crate::repo_scan_policy::check_deadline()?;
        }
        let Some(from_idx) = file_idx_by_path.get(&file.rel_path).copied() else {
            continue;
        };
        let mut edges: BTreeMap<(String, String, Option<String>), usize> = BTreeMap::new();
        for (call_index, call) in file.calls.iter().enumerate() {
            if call_index % 256 == 0 {
                crate::repo_scan_policy::check_deadline()?;
            }
            let Some(candidates) = symbol_by_name.get(&call.name) else {
                continue;
            };
            if candidates.len() != 1 {
                continue;
            }
            let target = &candidates[0];
            let key = (
                target.file_rel_path.clone(),
                target.name.clone(),
                call.from_symbol.clone(),
            );
            match edges.entry(key) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    let (to_file, to_symbol, from_symbol) = entry.key();
                    crate::repo_scan_policy::charge_generated_work(
                        1,
                        to_file
                            .len()
                            .saturating_add(to_symbol.len())
                            .saturating_add(from_symbol.as_deref().map_or(0, str::len)),
                        "polyglot reference-edge index",
                    )?;
                    entry.insert(1);
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    *entry.get_mut() += 1;
                }
            }
        }
        for ((to_file, to_symbol, from_symbol), call_count) in edges {
            crate::repo_scan_policy::charge_generated_work(
                1,
                to_file
                    .len()
                    .saturating_add(to_symbol.len())
                    .saturating_add(from_symbol.as_deref().map_or(0, str::len)),
                "polyglot reference output",
            )?;
            scan.files[from_idx].references.push(FileReference {
                same_file: to_file == file.rel_path,
                to_file,
                to_symbol,
                call_count,
                from_symbol,
            });
        }
    }
    Ok(())
}

fn resolve_polyglot_routes(
    scan: &mut WorkspaceScan,
    extracted: &[ExtractedFile],
    symbol_by_name: &HashMap<String, Vec<SymbolInfo>>,
) -> Result<(), ScanError> {
    for (file_index, file) in extracted.iter().enumerate() {
        if file_index % 256 == 0 {
            crate::repo_scan_policy::check_deadline()?;
        }
        for route in &file.unresolved_routes {
            crate::repo_scan_policy::charge_generated_work(
                1,
                route
                    .method
                    .len()
                    .saturating_add(route.path.len())
                    .saturating_add(route.handler_fn.len())
                    .saturating_add(route.source_file.len())
                    .saturating_add(route.reason.len()),
                "unresolved route output",
            )?;
            scan.diagnostics.unresolved_routes.push(route.clone());
        }
    }
    resolve_django_routes(scan, extracted, symbol_by_name)?;
    for (file_index, file) in extracted.iter().enumerate() {
        if file_index % 256 == 0 {
            crate::repo_scan_policy::check_deadline()?;
        }
        for (route_index, route) in file.routes.iter().enumerate() {
            if route_index % 256 == 0 {
                crate::repo_scan_policy::check_deadline()?;
            }
            if route.framework.as_deref() == Some("django") {
                continue;
            }
            crate::repo_scan_policy::charge_generated_work(
                1,
                route
                    .path
                    .len()
                    .saturating_add(route.source_file.len())
                    .saturating_add(match &route.handler {
                        RouteHandler::Inline => 8,
                        RouteHandler::Named(name) | RouteHandler::Django(name) => name.len(),
                        RouteHandler::Resolved { name, file, .. } => name.len().saturating_add(file.len()),
                    }),
                "scan output",
            )?;
            match &route.handler {
                RouteHandler::Inline => {
                    scan.routes.push(RouteHit {
                        method: route.method.clone(),
                        path: route.path.clone(),
                        handler_fn: "<inline>".to_string(),
                        framework: route.framework.clone(),
                        handler_file: Some(route.source_file.clone()),
                        handler_line: Some(route.source_line),
                        source_file: route.source_file.clone(),
                        source_line: route.source_line,
                    });
                }
                RouteHandler::Named(handler_fn) => {
                    let (handler_file, handler_line, reason) = resolve_route_handler(handler_fn, file, symbol_by_name)?;
                    if let Some(reason) = reason {
                        crate::repo_scan_policy::charge_generated_work(
                            1,
                            route
                                .method
                                .len()
                                .saturating_add(route.path.len())
                                .saturating_add(handler_fn.len())
                                .saturating_add(route.source_file.len())
                                .saturating_add(reason.len()),
                            "unresolved named-route output",
                        )?;
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
                        framework: route.framework.clone(),
                        handler_file,
                        handler_line,
                        source_file: route.source_file.clone(),
                        source_line: route.source_line,
                    });
                }
                RouteHandler::Resolved { name, file, line } => {
                    scan.routes.push(RouteHit {
                        method: route.method.clone(),
                        path: route.path.clone(),
                        handler_fn: name.clone(),
                        framework: route.framework.clone(),
                        handler_file: Some(file.clone()),
                        handler_line: Some(*line),
                        source_file: route.source_file.clone(),
                        source_line: route.source_line,
                    });
                }
                RouteHandler::Django(_) => {}
            }
        }
    }
    Ok(())
}

fn resolve_django_routes(
    scan: &mut WorkspaceScan,
    extracted: &[ExtractedFile],
    symbol_by_name: &HashMap<String, Vec<SymbolInfo>>,
) -> Result<(), ScanError> {
    let mut django_files = Vec::new();
    for file in extracted.iter().filter(|file| {
        file.routes
            .iter()
            .any(|route| route.framework.as_deref() == Some("django"))
            || !file.django_includes.is_empty()
    }) {
        crate::repo_scan_policy::charge_generated_work(1, std::mem::size_of::<&ExtractedFile>(), "Django file index")?;
        django_files.push(file);
    }
    if django_files.is_empty() {
        return Ok(());
    }
    let module_index = django_module_index(&django_files)?;
    let mut extracted_paths = HashSet::new();
    for file in extracted {
        crate::repo_scan_policy::charge_generated_work(1, std::mem::size_of::<&str>(), "Django extracted-path lookup")?;
        extracted_paths.insert(file.rel_path.as_str());
    }
    let mut claimed_files: HashSet<usize> = HashSet::new();
    let mut dynamic_include_sources: HashSet<usize> = HashSet::new();
    for (file_index, file) in django_files.iter().enumerate() {
        if file_index % 256 == 0 {
            crate::repo_scan_policy::check_deadline()?;
        }
        for (include_index, include) in file.django_includes.iter().enumerate() {
            if include_index % 256 == 0 {
                crate::repo_scan_policy::check_deadline()?;
            }
            match &include.target {
                DjangoIncludeTarget::Module(module) => {
                    let matches = module_index.get(module).map(Vec::as_slice).unwrap_or_default();
                    for index in matches {
                        crate::repo_scan_policy::charge_generated_work(
                            1,
                            std::mem::size_of::<usize>(),
                            "Django claimed-file index",
                        )?;
                        claimed_files.insert(*index);
                    }
                    if matches.len() != 1 {
                        let reason = if matches.is_empty() {
                            "include_not_found"
                        } else {
                            "include_ambiguous"
                        };
                        crate::repo_scan_policy::charge_generated_work(
                            1,
                            "ANY"
                                .len()
                                .saturating_add(include.prefix.len())
                                .saturating_add("include(\"\")".len())
                                .saturating_add(module.len())
                                .saturating_add(include.source_file.len())
                                .saturating_add(reason.len()),
                            "Django unresolved-include output",
                        )?;
                        scan.diagnostics.unresolved_routes.push(UnresolvedRoute {
                            method: "ANY".to_string(),
                            path: include.prefix.clone(),
                            handler_fn: format!("include(\"{module}\")"),
                            source_file: include.source_file.clone(),
                            source_line: include.source_line,
                            reason: reason.to_string(),
                        });
                    }
                }
                DjangoIncludeTarget::Dynamic(expression) => {
                    crate::repo_scan_policy::charge_generated_work(
                        1,
                        std::mem::size_of::<usize>(),
                        "Django dynamic-include source index",
                    )?;
                    dynamic_include_sources.insert(file_index);
                    crate::repo_scan_policy::charge_generated_work(
                        1,
                        "ANY"
                            .len()
                            .saturating_add(include.prefix.len())
                            .saturating_add("include()".len())
                            .saturating_add(expression.len())
                            .saturating_add(include.source_file.len())
                            .saturating_add("include_dynamic".len()),
                        "Django unresolved-include output",
                    )?;
                    scan.diagnostics.unresolved_routes.push(UnresolvedRoute {
                        method: "ANY".to_string(),
                        path: include.prefix.clone(),
                        handler_fn: format!("include({expression})"),
                        source_file: include.source_file.clone(),
                        source_line: include.source_line,
                        reason: "include_dynamic".to_string(),
                    });
                }
            }
        }
    }
    let mut settings_roots = Vec::new();
    for (index, file) in django_files.iter().enumerate() {
        if has_sibling_settings(file, &extracted_paths) {
            crate::repo_scan_policy::charge_generated_work(
                1,
                std::mem::size_of::<usize>(),
                "Django settings-root index",
            )?;
            settings_roots.push(index);
        }
    }
    let roots: Vec<usize> = if settings_roots.is_empty() {
        let mut roots = Vec::new();
        for index in 0..django_files.len() {
            if !claimed_files.contains(&index)
                && (dynamic_include_sources.is_empty() || dynamic_include_sources.contains(&index))
            {
                crate::repo_scan_policy::charge_generated_work(
                    1,
                    std::mem::size_of::<usize>(),
                    "Django route-root index",
                )?;
                roots.push(index);
            }
        }
        roots
    } else {
        settings_roots
    };
    for root_index in roots {
        crate::repo_scan_policy::check_deadline()?;
        expand_django_routes_iterative(root_index, &django_files, &module_index, symbol_by_name, scan)?;
    }
    Ok(())
}

fn has_sibling_settings(file: &ExtractedFile, extracted_paths: &HashSet<&str>) -> bool {
    let settings = Path::new(&file.rel_path)
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .join("settings.py")
        .display()
        .to_string();
    extracted_paths.contains(settings.as_str())
}

fn django_module_index(files: &[&ExtractedFile]) -> Result<HashMap<String, Vec<usize>>, ScanError> {
    let mut index: HashMap<String, Vec<usize>> = HashMap::new();
    for (file_index, file) in files.iter().enumerate() {
        if file_index % 256 == 0 {
            crate::repo_scan_policy::check_deadline()?;
        }
        let Some(without_extension) = file.rel_path.strip_suffix(".py") else {
            continue;
        };
        let component_count = without_extension.split('/').count();
        crate::repo_scan_policy::charge_generated_work(
            component_count,
            component_count.saturating_mul(std::mem::size_of::<&str>()),
            "Django module path components",
        )?;
        let components: Vec<&str> = without_extension.split('/').collect();
        for start in 0..components.len() {
            let key_len = components[start..]
                .iter()
                .map(|component| component.len())
                .sum::<usize>()
                .saturating_add(components.len().saturating_sub(start + 1));
            crate::repo_scan_policy::charge_generated_work(
                1,
                key_len.saturating_add(std::mem::size_of::<usize>()),
                "Django module suffix index",
            )?;
            index.entry(components[start..].join(".")).or_default().push(file_index);
        }
    }
    Ok(index)
}

enum DjangoExpansionWork {
    Enter {
        file_index: usize,
        prefix: String,
        depth: usize,
    },
    Exit {
        file_index: usize,
    },
}

fn expand_django_routes_iterative(
    root_index: usize,
    django_files: &[&ExtractedFile],
    module_index: &HashMap<String, Vec<usize>>,
    symbol_by_name: &HashMap<String, Vec<SymbolInfo>>,
    scan: &mut WorkspaceScan,
) -> Result<(), ScanError> {
    crate::repo_scan_policy::charge_generated_work(1, 0, "Django route expansion")?;
    let mut work = vec![DjangoExpansionWork::Enter {
        file_index: root_index,
        prefix: String::new(),
        depth: 0,
    }];
    let mut active = HashSet::new();
    let mut expansion_states = 0_usize;

    while let Some(next) = work.pop() {
        crate::repo_scan_policy::check_deadline()?;
        match next {
            DjangoExpansionWork::Exit { file_index } => {
                active.remove(&file_index);
            }
            DjangoExpansionWork::Enter {
                file_index,
                prefix,
                depth,
            } => {
                expansion_states = expansion_states.saturating_add(1);
                if expansion_states > MAX_DJANGO_EXPANSION_STATES {
                    return Err(ScanError::Policy(format!(
                        "Django route expansion exceeded {MAX_DJANGO_EXPANSION_STATES} states"
                    )));
                }
                crate::repo_scan_policy::check_depth(depth)?;
                if !active.insert(file_index) {
                    continue;
                }
                let file = django_files[file_index];
                work.push(DjangoExpansionWork::Exit { file_index });

                for (route_index, route) in file
                    .routes
                    .iter()
                    .filter(|route| route.framework.as_deref() == Some("django"))
                    .enumerate()
                {
                    if route_index % 256 == 0 {
                        crate::repo_scan_policy::check_deadline()?;
                    }
                    let RouteHandler::Django(handler) = &route.handler else {
                        continue;
                    };
                    crate::repo_scan_policy::charge_generated_work(
                        1,
                        prefix
                            .len()
                            .saturating_add(route.path.len())
                            .saturating_add(handler.len())
                            .saturating_add(route.source_file.len()),
                        "Django route expansion",
                    )?;
                    let (handler_file, handler_line, reason) = resolve_django_handler(handler, file, symbol_by_name)?;
                    let path = join_django_paths(&prefix, &route.path);
                    if let Some(reason) = reason {
                        crate::repo_scan_policy::charge_generated_work(
                            1,
                            route
                                .method
                                .len()
                                .saturating_add(path.len())
                                .saturating_add(handler.len())
                                .saturating_add(route.source_file.len())
                                .saturating_add(reason.len()),
                            "unresolved Django-route output",
                        )?;
                        scan.diagnostics.unresolved_routes.push(UnresolvedRoute {
                            method: route.method.clone(),
                            path: path.clone(),
                            handler_fn: handler.clone(),
                            source_file: route.source_file.clone(),
                            source_line: route.source_line,
                            reason: reason.to_string(),
                        });
                    }
                    scan.routes.push(RouteHit {
                        method: route.method.clone(),
                        path,
                        handler_fn: handler.clone(),
                        framework: Some("django".to_string()),
                        handler_file,
                        handler_line,
                        source_file: route.source_file.clone(),
                        source_line: route.source_line,
                    });
                }

                for include in file.django_includes.iter().rev() {
                    crate::repo_scan_policy::check_deadline()?;
                    let DjangoIncludeTarget::Module(module) = &include.target else {
                        continue;
                    };
                    let matches = module_index.get(module).map(Vec::as_slice).unwrap_or_default();
                    if matches.len() != 1 {
                        continue;
                    }
                    let estimated_bytes = prefix
                        .len()
                        .saturating_add(include.prefix.len())
                        .saturating_add(module.len());
                    crate::repo_scan_policy::charge_generated_work(1, estimated_bytes, "Django route expansion")?;
                    work.push(DjangoExpansionWork::Enter {
                        file_index: matches[0],
                        prefix: join_django_paths(&prefix, &include.prefix),
                        depth: depth.saturating_add(1),
                    });
                }
            }
        }
    }
    Ok(())
}

type HandlerResolution = (Option<String>, Option<usize>, Option<&'static str>);

fn resolve_django_handler(
    handler: &str,
    source_file: &ExtractedFile,
    symbol_by_name: &HashMap<String, Vec<SymbolInfo>>,
) -> Result<HandlerResolution, ScanError> {
    let trimmed = handler.trim();
    let expression = trimmed
        .find(".as_view(")
        .map_or(trimmed, |as_view_index| &trimmed[..as_view_index]);
    let lookup = expression.rsplit('.').next().unwrap_or(expression);
    let Some(candidates) = symbol_by_name.get(lookup) else {
        return Ok((None, None, Some("not_found")));
    };
    if let Some(module_hint) = expression
        .rsplit_once('.')
        .map(|(module, _)| module.rsplit('.').next().unwrap_or(module))
    {
        let expected = format!("/{module_hint}.py");
        if let Some(hinted) = unique_symbol_candidate(candidates, |symbol| {
            (symbol.file_rel_path.ends_with(&expected) || symbol.file_rel_path == format!("{module_hint}.py"))
                && symbol.crate_name == source_file.package_name
        })? {
            return Ok((Some(hinted.file_rel_path.clone()), Some(hinted.line), None));
        }
    }
    resolve_route_handler(lookup, source_file, symbol_by_name)
}

fn join_django_paths(prefix: &str, path: &str) -> String {
    if prefix.is_empty() {
        return path.to_string();
    }
    if path.is_empty() {
        return prefix.to_string();
    }
    let child = path
        .trim_start_matches('/')
        .strip_prefix('^')
        .unwrap_or(path.trim_start_matches('/'));
    format!("{}/{child}", prefix.trim_end_matches('/'))
}

fn resolve_route_handler(
    handler_fn: &str,
    source_file: &ExtractedFile,
    symbol_by_name: &HashMap<String, Vec<SymbolInfo>>,
) -> Result<HandlerResolution, ScanError> {
    if let Some(binding) = source_file.local_bindings.get(handler_fn) {
        return Ok((Some(source_file.rel_path.clone()), Some(binding.line), None));
    }
    let Some(candidates) = symbol_by_name.get(handler_fn) else {
        return Ok((None, None, Some("not_found")));
    };
    let same_file = unique_symbol_candidate(candidates, |symbol| symbol.file_rel_path == source_file.rel_path)?;
    let pick = if same_file.is_some() {
        same_file
    } else {
        let same_package =
            unique_symbol_candidate(candidates, |symbol| same_route_resolution_package(source_file, symbol))?;
        if same_package.is_some() {
            same_package
        } else if !is_go_path(&source_file.rel_path) && candidates.len() == 1 {
            candidates.first()
        } else {
            None
        }
    };
    if let Some(symbol) = pick {
        Ok((Some(symbol.file_rel_path.clone()), Some(symbol.line), None))
    } else {
        Ok((None, None, Some("ambiguous")))
    }
}

fn unique_symbol_candidate(
    candidates: &[SymbolInfo],
    predicate: impl Fn(&SymbolInfo) -> bool,
) -> Result<Option<&SymbolInfo>, ScanError> {
    let mut found = None;
    for (candidate_index, candidate) in candidates.iter().enumerate() {
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

fn build_referenced_by(scan: &mut WorkspaceScan) -> Result<(), ScanError> {
    let mut inverse: HashMap<String, HashSet<String>> = HashMap::new();
    for (file_index, file) in scan.files.iter().enumerate() {
        if file_index % 256 == 0 {
            crate::repo_scan_policy::check_deadline()?;
        }
        for (reference_index, reference) in file.references.iter().enumerate() {
            if reference_index % 256 == 0 {
                crate::repo_scan_policy::check_deadline()?;
            }
            if !reference.same_file {
                crate::repo_scan_policy::charge_generated_work(
                    1,
                    reference.to_file.len().saturating_add(file.rel_path.len()),
                    "polyglot inverse-reference index",
                )?;
                inverse
                    .entry(reference.to_file.clone())
                    .or_default()
                    .insert(file.rel_path.clone());
            }
        }
    }
    for (file_index, file) in scan.files.iter_mut().enumerate() {
        if file_index % 256 == 0 {
            crate::repo_scan_policy::check_deadline()?;
        }
        if let Some(refs) = inverse.remove(&file.rel_path) {
            crate::repo_scan_policy::charge_generated_work(
                refs.len(),
                refs.len().saturating_mul(std::mem::size_of::<String>()),
                "polyglot inverse-reference output index",
            )?;
            let mut refs: Vec<String> = refs.into_iter().collect();
            refs.sort();
            file.referenced_by = refs;
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, Default)]
struct FileRouteFrameworks {
    nextjs: bool,
    nuxt: bool,
    sveltekit: bool,
}

/// File-route precision bar: path conventions activate only below a package
/// scope whose dependency maps name the corresponding framework. Dynamic
/// `[param]` segments stay verbatim; route/server methods narrow only when an
/// exported HTTP-verb symbol was already extracted from that same file.
fn collect_file_based_routes(
    root: &Path,
    extracted: &[ExtractedFile],
    scan: &mut WorkspaceScan,
) -> Result<(), ScanError> {
    let package_scopes = package_framework_scopes(root)?;
    for (file_index, file) in extracted.iter().enumerate() {
        if file_index % 256 == 0 {
            crate::repo_scan_policy::check_deadline()?;
        }
        let Some((scope_directory, frameworks)) = framework_scope_for_file(&file.rel_path, &package_scopes)? else {
            continue;
        };
        let scope_relative = Path::new(&file.rel_path)
            .strip_prefix(scope_directory)
            .unwrap_or_else(|_| Path::new(&file.rel_path))
            .display()
            .to_string();
        if frameworks.nextjs {
            if let Some((path, narrow_methods)) = nextjs_file_route(&scope_relative) {
                push_file_route_hits(scan, file, "nextjs", path, narrow_methods)?;
            }
        }
        if frameworks.nuxt {
            if let Some(path) = nuxt_file_route(&scope_relative) {
                push_file_route_hits(scan, file, "nuxt", path, false)?;
            }
        }
        if frameworks.sveltekit {
            if let Some((path, narrow_methods)) = sveltekit_file_route(&scope_relative) {
                push_file_route_hits(scan, file, "sveltekit", path, narrow_methods)?;
            }
        }
    }
    Ok(())
}

fn package_framework_scopes(root: &Path) -> Result<HashMap<PathBuf, FileRouteFrameworks>, ScanError> {
    let mut manifests = Vec::new();
    let mut discovery_error = None;
    walk_dir(root, root, &mut |rel, abs| {
        if discovery_error.is_some() {
            return;
        }
        if rel.file_name().and_then(|name| name.to_str()) != Some("package.json") {
            return;
        }
        let bytes = rel
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .as_os_str()
            .as_encoded_bytes()
            .len()
            .saturating_add(abs.as_os_str().as_encoded_bytes().len());
        if let Err(error) = crate::repo_scan_policy::charge_generated_work(1, bytes, "package manifest discovery index")
        {
            discovery_error = Some(error);
            return;
        }
        manifests.push((
            rel.parent().unwrap_or_else(|| Path::new("")).to_path_buf(),
            abs.to_path_buf(),
        ));
    })?;
    if let Some(error) = discovery_error {
        return Err(error);
    }
    let mut scopes = HashMap::with_capacity(manifests.len());
    for (directory, manifest) in manifests {
        crate::repo_scan_policy::charge_generated_work(
            1,
            directory.as_os_str().as_encoded_bytes().len(),
            "file-route package scope",
        )?;
        scopes.insert(directory, package_json_frameworks(&manifest)?);
    }
    Ok(scopes)
}

fn package_json_frameworks(path: &Path) -> Result<FileRouteFrameworks, ScanError> {
    let text = crate::workspace_scan::read_scan_to_string(path)?;
    crate::repo_scan_policy::charge_source_parse_work(&text, "package.json parser document")?;
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) else {
        return Ok(FileRouteFrameworks::default());
    };
    let mut frameworks = FileRouteFrameworks::default();
    for section in [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ] {
        if let Some(dependencies) = json.get(section).and_then(serde_json::Value::as_object) {
            frameworks.nextjs |= dependencies.contains_key("next");
            frameworks.nuxt |= dependencies.contains_key("nuxt");
            frameworks.sveltekit |= dependencies.contains_key("@sveltejs/kit");
        }
    }
    Ok(frameworks)
}

fn framework_scope_for_file<'path, 'scope>(
    rel_path: &'path str,
    scopes: &'scope HashMap<PathBuf, FileRouteFrameworks>,
) -> Result<Option<(&'path Path, &'scope FileRouteFrameworks)>, ScanError> {
    let mut directory = Path::new(rel_path).parent();
    while let Some(candidate) = directory {
        crate::repo_scan_policy::check_deadline()?;
        if let Some(frameworks) = scopes.get(candidate) {
            return Ok(Some((candidate, frameworks)));
        }
        directory = candidate.parent();
    }
    Ok(None)
}

fn nextjs_file_route(rel_path: &str) -> Option<(String, bool)> {
    let parts = path_parts(rel_path);
    let file_name = parts.last()?;
    let extension = Path::new(file_name).extension()?.to_str()?;
    let stem = Path::new(file_name).file_stem()?.to_str()?;
    if matches!(extension, "js" | "jsx" | "ts" | "tsx") {
        if let Some(pages_index) = router_root_index(&parts, "pages") {
            if matches!(stem, "_app" | "_document" | "_error") {
                return None;
            }
            let is_api = parts.get(pages_index + 1) == Some(&"api");
            if is_api && stem.starts_with('_') {
                return None;
            }
            let path = conventional_page_path(&parts[pages_index + 1..], stem);
            return Some((path, is_api));
        }
    }
    let app_index = router_root_index(&parts, "app")?;
    if stem == "page" && matches!(extension, "js" | "jsx" | "ts" | "tsx") {
        let segments = normalize_next_app_segments(&parts[app_index + 1..parts.len() - 1]);
        return Some((owned_segments_to_route_path(&segments), false));
    }
    if stem == "route" && matches!(extension, "js" | "ts") {
        let segments = normalize_next_app_segments(&parts[app_index + 1..parts.len() - 1]);
        return Some((owned_segments_to_route_path(&segments), true));
    }
    None
}

fn nuxt_file_route(rel_path: &str) -> Option<String> {
    let parts = path_parts(rel_path);
    let file_name = parts.last()?;
    if Path::new(file_name)
        .extension()
        .and_then(|extension| extension.to_str())
        != Some("vue")
    {
        return None;
    }
    let stem = Path::new(file_name).file_stem()?.to_str()?;
    let pages_index = router_root_index(&parts, "pages")?;
    Some(conventional_page_path(&parts[pages_index + 1..], stem))
}

fn sveltekit_file_route(rel_path: &str) -> Option<(String, bool)> {
    let parts = path_parts(rel_path);
    if parts.first() != Some(&"src") || parts.get(1) != Some(&"routes") {
        return None;
    }
    let routes_index = 1;
    let file_name = parts.last()?;
    let is_page = *file_name == "+page.svelte";
    let is_server = matches!(*file_name, "+server.js" | "+server.ts");
    if !is_page && !is_server {
        return None;
    }
    let segments: Vec<&str> = parts[routes_index + 1..parts.len() - 1]
        .iter()
        .copied()
        .filter(|segment| !(segment.starts_with('(') && segment.ends_with(')')))
        .collect();
    Some((segments_to_route_path(&segments), is_server))
}

fn router_root_index(parts: &[&str], directory: &str) -> Option<usize> {
    if parts.first() == Some(&directory) {
        Some(0)
    } else if parts.first() == Some(&"src") && parts.get(1) == Some(&directory) {
        Some(1)
    } else {
        None
    }
}

fn normalize_next_app_segments(segments: &[&str]) -> Vec<String> {
    segments
        .iter()
        .filter_map(|segment| {
            if segment.starts_with('@') {
                return None;
            }
            for marker in ["(..)(..)", "(...)", "(..)", "(.)"] {
                if let Some(name) = segment.strip_prefix(marker) {
                    return (!name.is_empty()).then(|| name.to_string());
                }
            }
            if segment.starts_with('(') && segment.ends_with(')') {
                None
            } else {
                Some((*segment).to_string())
            }
        })
        .collect()
}

fn path_parts(path: &str) -> Vec<&str> {
    path.split(['/', '\\']).filter(|part| !part.is_empty()).collect()
}

fn conventional_page_path(parts_after_pages: &[&str], stem: &str) -> String {
    let mut segments = parts_after_pages[..parts_after_pages.len().saturating_sub(1)].to_vec();
    if stem != "index" {
        segments.push(stem);
    }
    segments_to_route_path(&segments)
}

fn segments_to_route_path(segments: &[&str]) -> String {
    if segments.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", segments.join("/"))
    }
}

fn owned_segments_to_route_path(segments: &[String]) -> String {
    if segments.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", segments.join("/"))
    }
}

fn push_file_route_hits(
    scan: &mut WorkspaceScan,
    file: &ExtractedFile,
    framework: &str,
    path: String,
    narrow_methods: bool,
) -> Result<(), ScanError> {
    const METHODS: [&str; 7] = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];
    let mut emitted = false;
    if narrow_methods {
        for method in METHODS {
            if let Some(symbol) = file
                .symbols
                .iter()
                .find(|symbol| symbol.is_pub && symbol.name == method)
            {
                push_one_file_route(scan, file, framework, &path, method, symbol.line)?;
                emitted = true;
            }
        }
    }
    if !emitted {
        push_one_file_route(scan, file, framework, &path, "ANY", 1)?;
    }
    Ok(())
}

fn push_one_file_route(
    scan: &mut WorkspaceScan,
    file: &ExtractedFile,
    framework: &str,
    path: &str,
    method: &str,
    line: usize,
) -> Result<(), ScanError> {
    crate::repo_scan_policy::charge_generated_work(
        1,
        method
            .len()
            .saturating_add(path.len())
            .saturating_add(framework.len())
            .saturating_add(file.rel_path.len().saturating_mul(3)),
        "file-route output",
    )?;
    scan.routes.push(RouteHit {
        method: method.to_string(),
        path: path.to_string(),
        handler_fn: file.rel_path.clone(),
        framework: Some(framework.to_string()),
        handler_file: Some(file.rel_path.clone()),
        handler_line: Some(line),
        source_file: file.rel_path.clone(),
        source_line: line,
    });
    Ok(())
}

fn roll_up_stats(scan: &mut WorkspaceScan) -> Result<(), ScanError> {
    let mut routes_by_crate = BTreeMap::new();
    let crate_by_file: HashMap<&str, &str> = scan
        .files
        .iter()
        .map(|file| (file.rel_path.as_str(), file.crate_name.as_str()))
        .collect();
    for (route_index, route) in scan.routes.iter().enumerate() {
        if route_index % 256 == 0 {
            crate::repo_scan_policy::check_deadline()?;
        }
        if let Some(crate_name) = route
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
        route_count: scan.routes.len(),
        file_reference_count: scan.files.iter().map(|f| f.references.len()).sum(),
        external_dep_count: scan.external_deps.len(),
        doc_coverage_files: scan.files.iter().filter(|f| f.doc_summary.is_some()).count(),
        routes_by_crate,
    };
    Ok(())
}

fn package_infos(root: &Path, scan: &WorkspaceScan, default_name: &str) -> Result<Vec<CrateInfo>, ScanError> {
    let mut packages: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for (file_index, file) in scan.files.iter().enumerate() {
        if file_index % 256 == 0 {
            crate::repo_scan_policy::check_deadline()?;
        }
        crate::repo_scan_policy::charge_generated_work(1, file.crate_name.len(), "polyglot package aggregation index")?;
        let entry = packages.entry(file.crate_name.clone()).or_insert((0, 0));
        entry.0 += 1;
        entry.1 += file.loc;
    }
    if packages.is_empty() {
        crate::repo_scan_policy::charge_generated_work(1, default_name.len(), "polyglot package aggregation index")?;
        packages.insert(default_name.to_string(), (0, 0));
    }
    crate::repo_scan_policy::charge_generated_work(
        1,
        root.as_os_str().as_encoded_bytes().len(),
        "polyglot package root path",
    )?;
    let root_path = root.display().to_string();
    packages
        .into_iter()
        .map(|(name, (file_count, total_loc))| {
            crate::repo_scan_policy::check_deadline()?;
            crate::repo_scan_policy::charge_generated_work(
                1,
                name.len().saturating_add(root_path.len()),
                "polyglot package output",
            )?;
            Ok(CrateInfo {
                rel_path: root_path.clone(),
                internal_deps: Vec::new(),
                name,
                file_count,
                total_loc,
            })
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
        .filter(|s| !s.is_empty() && s.len() <= crate::workspace_scan::SCAN_METADATA_MAX_BYTES)
        .unwrap_or("repo")
        .to_string()
}

fn bounded_package_name(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty() && value.len() <= crate::workspace_scan::SCAN_METADATA_MAX_BYTES).then(|| value.to_string())
}

fn package_json_name(path: &Path) -> Option<String> {
    let text = crate::workspace_scan::read_optional_scan_to_string(path).ok()??;
    crate::repo_scan_policy::charge_source_parse_work(&text, "package.json metadata parser").ok()?;
    #[derive(serde::Deserialize)]
    struct PackageName {
        name: Option<String>,
    }
    serde_json::from_str::<PackageName>(&text)
        .ok()?
        .name
        .as_deref()
        .and_then(bounded_package_name)
}

fn pyproject_name(path: &Path) -> Option<String> {
    let text = crate::workspace_scan::read_optional_scan_to_string(path).ok()??;
    crate::repo_scan_policy::charge_source_parse_work(&text, "pyproject.toml metadata parser").ok()?;
    let mut in_project = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_project = trimmed == "[project]";
        } else if in_project && trimmed.starts_with("name") {
            return quoted_value(trimmed).and_then(|value| bounded_package_name(&value));
        }
    }
    None
}

fn setup_cfg_name(path: &Path) -> Option<String> {
    let text = crate::workspace_scan::read_optional_scan_to_string(path).ok()??;
    crate::repo_scan_policy::charge_source_parse_work(&text, "setup.cfg metadata parser").ok()?;
    let mut in_metadata = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_metadata = trimmed == "[metadata]";
        } else if in_metadata && trimmed.starts_with("name") {
            return trimmed
                .split_once('=')
                .and_then(|(_, value)| bounded_package_name(value));
        }
    }
    None
}

fn quoted_value(line: &str) -> Option<String> {
    let (_, value) = line.split_once('=')?;
    Some(value.trim().trim_matches('"').trim_matches('\'').to_string())
}

fn has_supported_file(root: &Path, exts: &[Option<&str>]) -> Result<bool, ScanError> {
    let mut found = false;
    walk_dir(root, root, &mut |_rel, abs| {
        if found {
            return;
        }
        let ext = abs.extension().and_then(|e| e.to_str());
        found = exts.contains(&ext);
    })?;
    Ok(found)
}

fn has_polyglot_non_rust_files(root: &Path, options: PolyglotScanOptions) -> Result<bool, ScanError> {
    let mut extensions = vec![Some("ts"), Some("tsx"), Some("py"), Some("vue")];
    if options.v2_enabled {
        extensions.extend([Some("js"), Some("jsx"), Some("mjs"), Some("cjs"), Some("go")]);
    }
    if options.v3_enabled {
        extensions.extend([
            Some("js"),
            Some("jsx"),
            Some("mjs"),
            Some("cjs"),
            Some("svelte"),
            Some("java"),
            Some("c"),
            Some("h"),
            Some("cpp"),
            Some("cc"),
            Some("cxx"),
            Some("hpp"),
            Some("hh"),
            Some("hxx"),
            Some("cs"),
            Some("rb"),
            Some("swift"),
            Some("php"),
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
    let v3_clean = [
        ".java", ".swift", ".php", ".cpp", ".cxx", ".hpp", ".hxx", ".cc", ".cs", ".rb", ".hh", ".c", ".h",
    ]
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
        .trim_end_matches(".svelte")
        .trim_end_matches(".go")
        .trim_end_matches(".rs")
        .replace(['/', '\\', '-'], "::");
    format!("{}::{}", package_name.replace('-', "_"), clean)
}

fn node_text(node: Node<'_>, src: &[u8]) -> String {
    node.utf8_text(src).unwrap_or_default().to_string()
}

fn field_ident(node: Node<'_>, src: &[u8], field: &str) -> Option<String> {
    let text = node.child_by_field_name(field)?.utf8_text(src).ok()?.trim();
    (!text.is_empty() && text.len() <= crate::workspace_scan::SCAN_METADATA_MAX_BYTES).then(|| text.to_string())
}

fn quoted_child_text(node: Node<'_>, src: &[u8], guard: &mut AstWalkGuard, depth: usize) -> Option<String> {
    if !guard.allow_depth(depth) {
        return None;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        let Ok(text) = child.utf8_text(src) else {
            continue;
        };
        if text.len() > crate::workspace_scan::SCAN_METADATA_MAX_BYTES {
            continue;
        }
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
        if let Ok(text) = node.utf8_text(src) {
            if !text.is_empty() && text.len() <= crate::workspace_scan::SCAN_METADATA_MAX_BYTES {
                out.push(text.to_string());
            }
        }
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
    let Ok(text) = node.utf8_text(src) else {
        return String::new();
    };
    let ident = text.rsplit(['.', ':']).next().unwrap_or(text).trim();
    if ident.is_empty() || ident.len() > crate::workspace_scan::SCAN_METADATA_MAX_BYTES {
        String::new()
    } else {
        ident.to_string()
    }
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

fn visit_rust_use_paths(
    tree: &syn::UseTree,
    guard: &mut AstWalkGuard,
    visitor: &mut impl FnMut(&[String]) -> Result<(), ScanError>,
) -> Result<(), ScanError> {
    fn walk(
        prefix: &mut Vec<String>,
        tree: &syn::UseTree,
        guard: &mut AstWalkGuard,
        visitor: &mut impl FnMut(&[String]) -> Result<(), ScanError>,
        depth: usize,
    ) -> Result<(), ScanError> {
        if !guard.allow_depth(depth) {
            return Ok(());
        }
        match tree {
            syn::UseTree::Path(p) => {
                let ident = p.ident.to_string();
                crate::repo_scan_policy::charge_generated_work(1, ident.len(), "Rust use prefix stack")?;
                prefix.push(ident);
                walk(prefix, &p.tree, guard, visitor, depth + 1)?;
                prefix.pop();
            }
            syn::UseTree::Name(n) => {
                let ident = n.ident.to_string();
                crate::repo_scan_policy::charge_generated_work(1, ident.len(), "Rust use leaf")?;
                prefix.push(ident);
                visitor(prefix)?;
                prefix.pop();
            }
            syn::UseTree::Rename(r) => {
                let ident = r.ident.to_string();
                crate::repo_scan_policy::charge_generated_work(1, ident.len(), "Rust use leaf")?;
                prefix.push(ident);
                visitor(prefix)?;
                prefix.pop();
            }
            syn::UseTree::Glob(_) => {
                crate::repo_scan_policy::charge_generated_work(1, 1, "Rust use leaf")?;
                prefix.push("*".to_string());
                visitor(prefix)?;
                prefix.pop();
            }
            syn::UseTree::Group(g) => {
                for item in &g.items {
                    walk(prefix, item, guard, visitor, depth + 1)?;
                }
            }
        }
        Ok(())
    }
    walk(&mut Vec::new(), tree, guard, visitor, 0)
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

    /// D-24: tree-sitter is error-tolerant, so a broken `.ts`/`.py`/`.java`
    /// file produced a `FileInfo` with no symbols — byte-identical to an empty
    /// one. Nothing recorded the parse failure.
    #[test]
    #[serial_test::serial]
    fn a_broken_polyglot_file_is_recorded_as_a_parse_failure() {
        let _env = EnvVarGuard::set(POLYGLOT_V3_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path();
        std::fs::write(root.join("good.ts"), "export function ok() { return 1; }\n").expect("good ts");
        // NB: brace-balanced on purpose — `scripts/unwrap-ratchet.sh` tracks
        // `#[cfg(test)]` scope by counting braces textually, so an unbalanced
        // literal here silently exposes the rest of this module to the ratchet.
        std::fs::write(root.join("broken.ts"), "export function ( <<< ,,, ===\n").expect("broken ts");
        std::fs::write(root.join("broken.py"), "def (:::\n  return\n").expect("broken py");
        // Genuinely empty: no symbols, but also no failure.
        std::fs::write(root.join("empty.ts"), "").expect("empty ts");

        let scan = run_repo_scan_at(root).expect("scan");
        let failed: Vec<&str> = scan
            .diagnostics
            .parse_failures
            .iter()
            .map(|f| f.rel_path.as_str())
            .collect();
        assert_eq!(
            failed,
            vec!["broken.py", "broken.ts"],
            "only the unparsable files are recorded, not the empty or good ones"
        );
        assert!(scan
            .diagnostics
            .parse_failures
            .iter()
            .any(|f| f.language == "typescript"));
        assert!(scan.diagnostics.parse_failures.iter().any(|f| f.language == "python"));

        // The broken file is still scanned with no symbols — which is exactly
        // why the diagnostic is what tells it apart from `empty.ts`.
        let broken = scan
            .files
            .iter()
            .find(|f| f.rel_path == "broken.ts")
            .expect("broken file is still scanned");
        assert_eq!(broken.symbol_count, 0);
    }
    use crate::test_support::EnvVarGuard;
    use std::collections::BTreeSet;

    #[test]
    fn configured_scan_budget_allows_bounded_repo_and_rejects_entry_overflow() {
        let root = tempfile::tempdir().expect("root");
        std::fs::write(root.path().join("package.json"), "{\"name\":\"bounded\"}").expect("package");
        std::fs::write(root.path().join("app.ts"), "export function bounded() { return 1; }\n").expect("source");
        let canonical = root.path().canonicalize().expect("canonical root");
        let policy = crate::repo_scan_policy::RepoScanPolicy::for_test_roots(
            vec![canonical.clone()],
            crate::repo_scan_policy::RepoScanLimits {
                max_depth: 4,
                max_files: 2,
                max_bytes: 1024 * 1024,
                max_file_bytes: 1024 * 1024,
                timeout: std::time::Duration::from_secs(5),
                ..crate::repo_scan_policy::RepoScanLimits::default()
            },
        );
        let scan = run_repo_scan_at_with_policy(&canonical, &policy).expect("bounded scan");
        assert!(scan.files.iter().any(|file| file.rel_path == "app.ts"));

        let tight = crate::repo_scan_policy::RepoScanPolicy::for_test_roots(
            vec![canonical.clone()],
            crate::repo_scan_policy::RepoScanLimits {
                max_files: 1,
                ..policy.limits()
            },
        );
        let error = run_repo_scan_at_with_policy(&canonical, &tight).expect_err("entry overflow");
        assert!(error.to_string().contains("filesystem entries"));
    }

    #[test]
    #[serial_test::serial]
    fn no_cargo_polyglot_rust_scan_rejects_excessive_generic_nesting() {
        let _v3 = EnvVarGuard::set(POLYGLOT_V3_ENV, "1");
        let root = tempfile::tempdir().expect("root");
        let nested = format!(
            "type Deep = {}u8{};\n",
            "Vec<".repeat(crate::workspace_scan::RUST_SYNTAX_MAX_DEPTH + 1),
            ">".repeat(crate::workspace_scan::RUST_SYNTAX_MAX_DEPTH + 1)
        );
        std::fs::write(root.path().join("nested.rs"), nested).expect("nested source");

        let error = run_repo_scan_at(root.path()).expect_err("polyglot Rust scan must reject nesting");
        assert!(error.to_string().contains("Rust syntax nesting"));
    }

    fn route_set(scan: &WorkspaceScan) -> BTreeSet<(String, String, String)> {
        scan.routes
            .iter()
            .map(|route| (route.method.clone(), route.path.clone(), route.handler_fn.clone()))
            .collect()
    }

    fn route_tuple(method: &str, path: &str, handler: &str) -> (String, String, String) {
        (method.to_string(), path.to_string(), handler.to_string())
    }

    fn framework_route_set(scan: &WorkspaceScan) -> BTreeSet<(String, String, String, String)> {
        scan.routes
            .iter()
            .filter_map(|route| {
                Some((
                    route.method.clone(),
                    route.path.clone(),
                    route.handler_fn.clone(),
                    route.framework.clone()?,
                ))
            })
            .collect()
    }

    fn framework_route_tuple(
        method: &str,
        path: &str,
        handler: &str,
        framework: &str,
    ) -> (String, String, String, String) {
        (
            method.to_string(),
            path.to_string(),
            handler.to_string(),
            framework.to_string(),
        )
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

    fn write_branching_django_fixture(root: &Path, levels: usize) {
        assert!(levels > 0);
        std::fs::create_dir_all(root.join("project")).expect("project");
        std::fs::write(root.join("project/settings.py"), "ROOT_URLCONF = 'project.urls'\n").expect("settings");
        std::fs::write(
            root.join("project/urls.py"),
            "from django.urls import include, path\nurlpatterns = [path('a/', include('level1.urls')), path('b/', include('level1.urls'))]\n",
        )
        .expect("root urls");
        for level in 1..=levels {
            let directory = root.join(format!("level{level}"));
            std::fs::create_dir_all(&directory).expect("level dir");
            let source = if level == levels {
                "from django.urls import path\nurlpatterns = [path('leaf/', views.leaf)]\n".to_string()
            } else {
                format!(
                    "from django.urls import include, path\nurlpatterns = [path('a/', include('level{}.urls')), path('b/', include('level{}.urls'))]\n",
                    level + 1,
                    level + 1
                )
            };
            std::fs::write(directory.join("urls.py"), source).expect("level urls");
        }
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
            ("Dark.cs", "class DarkCs {}\n"),
            ("dark.rb", "class DarkRuby; end\n"),
            ("Dark.swift", "class DarkSwift {}\n"),
            ("dark.php", "<?php class DarkPhp {}\n"),
        ] {
            std::fs::write(root.join(name), source).expect("dark V3 source");
        }
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v3_csharp_fixture_extracts_exact_qualified_symbols() {
        let _env = EnvVarGuard::set(POLYGLOT_V3_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("Service.cs"),
            r#"using Clock = System.DateTime;
namespace Demo.Api;
public interface IRepository { void Find(); }
internal struct HiddenStruct { }
public record Item(string Id);
public enum State { Ready }
public delegate void Changed();
public class Service {
    public const int Max = 10;
    private static readonly string Secret = "x";
    public void Run() {}
    void Hidden() {}
    private Item referenced;
}
"#,
        )
        .expect("csharp");

        let scan = run_repo_scan_at(tmp.path()).expect("scan");
        assert_eq!(
            symbol_set(&scan, "Service.cs"),
            BTreeSet::from([
                ("class".to_string(), "HiddenStruct".to_string()),
                ("class".to_string(), "Item".to_string()),
                ("class".to_string(), "Service".to_string()),
                ("class".to_string(), "State".to_string()),
                ("const".to_string(), "Max".to_string()),
                ("const".to_string(), "Secret".to_string()),
                ("interface".to_string(), "IRepository".to_string()),
                ("method".to_string(), "Demo.Api.IRepository.Find".to_string()),
                ("method".to_string(), "Demo.Api.Service.Hidden".to_string()),
                ("method".to_string(), "Demo.Api.Service.Run".to_string()),
                ("type".to_string(), "Changed".to_string()),
                ("type".to_string(), "Clock".to_string()),
            ])
        );
        assert!(!symbol_is_pub(&scan, "Service.cs", "class", "HiddenStruct"));
        assert!(!symbol_is_pub(&scan, "Service.cs", "method", "Demo.Api.Service.Hidden"));
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v3_ruby_fixture_extracts_exact_qualified_symbols() {
        let _env = EnvVarGuard::set(POLYGLOT_V3_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("service.rb"),
            r#"module Demo
  class Service
    LIMIT = 10
    def run; end
    def self.build; end
    class << self
      def configured; end
    end
    private
    def helper
      Phantom = 1
    end
  end
end
Referenced::Only
"#,
        )
        .expect("ruby");

        let scan = run_repo_scan_at(tmp.path()).expect("scan");
        assert_eq!(
            symbol_set(&scan, "service.rb"),
            BTreeSet::from([
                ("class".to_string(), "Demo".to_string()),
                ("class".to_string(), "Service".to_string()),
                ("const".to_string(), "LIMIT".to_string()),
                ("method".to_string(), "Demo::Service#helper".to_string()),
                ("method".to_string(), "Demo::Service#run".to_string()),
                ("method".to_string(), "Demo::Service.build".to_string()),
                ("method".to_string(), "Demo::Service.configured".to_string()),
            ])
        );
        assert!(!symbol_is_pub(&scan, "service.rb", "method", "Demo::Service#helper"));
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v3_swift_fixture_extracts_exact_symbols() {
        let _env = EnvVarGuard::set(POLYGLOT_V3_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("Service.swift"),
            r#"public protocol Repository { func find() }
public struct Item { public let id: String; var mutable: Int }
enum State { case ready }
public class Service {
    public static let limit = 10
    public func run() {}
}
public actor Worker { public func work() {} }
public typealias Identifier = String
public func topLevel() {}
let referenceOnly = Service.self
"#,
        )
        .expect("swift");

        let scan = run_repo_scan_at(tmp.path()).expect("scan");
        assert_eq!(
            symbol_set(&scan, "Service.swift"),
            BTreeSet::from([
                ("class".to_string(), "Item".to_string()),
                ("class".to_string(), "Service".to_string()),
                ("class".to_string(), "State".to_string()),
                ("class".to_string(), "Worker".to_string()),
                ("const".to_string(), "id".to_string()),
                ("const".to_string(), "limit".to_string()),
                ("fn".to_string(), "topLevel".to_string()),
                ("interface".to_string(), "Repository".to_string()),
                ("method".to_string(), "find".to_string()),
                ("method".to_string(), "run".to_string()),
                ("method".to_string(), "work".to_string()),
                ("type".to_string(), "Identifier".to_string()),
            ])
        );
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v3_php_fixture_extracts_exact_qualified_symbols() {
        let _env = EnvVarGuard::set(POLYGLOT_V3_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("Service.php"),
            r#"<?php
namespace Demo\Api;
interface Repository { public function find(); }
trait Logs { protected function log() {} }
class Service {
    public const LIMIT = 10;
    private const SECRET = 1;
    public function run() {}
    public function visible(string $private = 'protected') { $private = 1; }
    private function helper() {}
}
function utility() {}
$phantom = Service::class;
"#,
        )
        .expect("php");

        let scan = run_repo_scan_at(tmp.path()).expect("scan");
        assert_eq!(
            symbol_set(&scan, "Service.php"),
            BTreeSet::from([
                ("class".to_string(), "Logs".to_string()),
                ("class".to_string(), "Service".to_string()),
                ("const".to_string(), "LIMIT".to_string()),
                ("const".to_string(), "SECRET".to_string()),
                ("fn".to_string(), "Demo\\Api\\utility".to_string()),
                ("interface".to_string(), "Repository".to_string()),
                ("method".to_string(), "Demo\\Api\\Logs::log".to_string()),
                ("method".to_string(), "Demo\\Api\\Repository::find".to_string()),
                ("method".to_string(), "Demo\\Api\\Service::helper".to_string()),
                ("method".to_string(), "Demo\\Api\\Service::run".to_string()),
                ("method".to_string(), "Demo\\Api\\Service::visible".to_string()),
            ])
        );
        assert!(!symbol_is_pub(
            &scan,
            "Service.php",
            "method",
            "Demo\\Api\\Service::helper"
        ));
        assert!(symbol_is_pub(
            &scan,
            "Service.php",
            "method",
            "Demo\\Api\\Service::visible"
        ));
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v3_aspnet_routes_are_precise_and_ignore_http_clients() {
        let _env = EnvVarGuard::set(POLYGLOT_V3_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("UsersController.cs"),
            r#"namespace Demo.Api;
[ApiController]
[Route("api/[controller]")]
public class UsersController : ControllerBase {
  [HttpGet]
  public void List() {}
  [HttpPost("{id}")]
  public void Update() {}
  [HttpGet(Name = "named-route")]
  public void Named() {}
  [HttpGet("tpl", Name = "templated-route")]
  public void Templated() {}
  [HttpGet("/absolute/[action]")]
  public void Absolute() {}
  [HttpGet("~/root/[controller]/[action]")]
  public void Tilde() {}
}
public class Client {
  public void Call() { client.GetAsync("/phantom"); }
}
"#,
        )
        .expect("csharp");
        let scan = run_repo_scan_at(tmp.path()).expect("scan");
        assert_eq!(
            route_set(&scan),
            BTreeSet::from([
                route_tuple("GET", "/api/Users", "Demo.Api.UsersController.List"),
                route_tuple("GET", "/api/Users", "Demo.Api.UsersController.Named"),
                route_tuple("POST", "/api/Users/{id}", "Demo.Api.UsersController.Update"),
                route_tuple("GET", "/api/Users/tpl", "Demo.Api.UsersController.Templated"),
                route_tuple("GET", "/absolute/Absolute", "Demo.Api.UsersController.Absolute"),
                route_tuple("GET", "/root/Users/Tilde", "Demo.Api.UsersController.Tilde"),
            ])
        );
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v3_rails_routes_expand_resources_and_track_prefixes() {
        let _env = EnvVarGuard::set(POLYGLOT_V3_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(tmp.path().join("config")).expect("config");
        std::fs::write(
            tmp.path().join("config/routes.rb"),
            r#"Rails.application.routes.draw do
  get "/health" => "health#show"
  post "/login", to: "sessions#create"
  namespace :api do
    scope "/v2" do
      get "/status" => "status#show"
    end
    resources :widgets
  end
  resources :photos, only: [:index]
  resources :albums, except: [:destroy]
  resources :cats, :dogs, only: :show
  scope module: "admin" do
    get "/module-only" => "dashboard#show"
  end
  scope as: "admin" do
    get "/as-only" => "plain#show"
  end
  get dynamic_path, to: "dynamic#show"
end
"#,
        )
        .expect("routes");
        std::fs::write(tmp.path().join("routes.rb"), "get \"/ignored\" => \"x#y\"\n").expect("outside routes");
        std::fs::write(tmp.path().join("client.rb"), "client.get(\"/phantom\")\n").expect("client");

        let scan = run_repo_scan_at(tmp.path()).expect("scan");
        let mut expected = BTreeSet::from([
            route_tuple("GET", "/health", "health#show"),
            route_tuple("POST", "/login", "sessions#create"),
            route_tuple("GET", "/api/v2/status", "api/status#show"),
            route_tuple("GET", "/photos", "photos#index"),
            route_tuple("GET", "/cats/:id", "cats#show"),
            route_tuple("GET", "/dogs/:id", "dogs#show"),
            route_tuple("GET", "/module-only", "admin/dashboard#show"),
            route_tuple("GET", "/as-only", "plain#show"),
        ]);
        for route in [
            route_tuple("GET", "/api/widgets", "api/widgets#index"),
            route_tuple("GET", "/api/widgets/:id", "api/widgets#show"),
            route_tuple("GET", "/api/widgets/new", "api/widgets#new"),
            route_tuple("POST", "/api/widgets", "api/widgets#create"),
            route_tuple("GET", "/api/widgets/:id/edit", "api/widgets#edit"),
            route_tuple("PATCH", "/api/widgets/:id", "api/widgets#update"),
            route_tuple("DELETE", "/api/widgets/:id", "api/widgets#destroy"),
        ] {
            expected.insert(route);
        }
        for route in [
            route_tuple("GET", "/albums", "albums#index"),
            route_tuple("GET", "/albums/:id", "albums#show"),
            route_tuple("GET", "/albums/new", "albums#new"),
            route_tuple("POST", "/albums", "albums#create"),
            route_tuple("GET", "/albums/:id/edit", "albums#edit"),
            route_tuple("PATCH", "/albums/:id", "albums#update"),
        ] {
            expected.insert(route);
        }
        assert_eq!(route_set(&scan), expected);
        assert!(scan
            .diagnostics
            .unresolved_routes
            .iter()
            .any(|route| route.path == "<dynamic>" && route.reason == "dynamic"));
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v3_laravel_routes_expand_resources_and_track_groups() {
        let _env = EnvVarGuard::set(POLYGLOT_V3_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(tmp.path().join("routes")).expect("routes");
        std::fs::write(
            tmp.path().join("routes/api.php"),
            r#"<?php
Route::get('/health', function () { return 'ok'; });
Route::post('/users', [UserController::class, 'store']);
Route::group(['prefix' => 'admin'], function () {
    Route::prefix('v1')->group(function () {
        Route::get('/functions', [Ctrl::class, 'index']);
        Route::get('/multi', function () {
            return [];
        });
        Route::get('/after-multi', [Ctrl::class, 'after']);
        Route::resource('photos', PhotoController::class);
        Route::apiResource('events', EventController::class);
    });
    Route::middleware('auth')->group(function () {
        Route::get('/guarded', [GuardController::class, 'index']);
    });
    Route::controller(Ctrl::class)->group(function () {
        Route::get('/controlled', [Ctrl::class, 'controlled']);
    });
    Route::get('/sibling', [SiblingController::class, 'index']);
});
Http::get('/phantom');
$client->post('/phantom');
"#,
        )
        .expect("routes");

        let scan = run_repo_scan_at(tmp.path()).expect("scan");
        let mut expected = BTreeSet::from([
            route_tuple("GET", "/health", "closure"),
            route_tuple("POST", "/users", "UserController::store"),
            route_tuple("GET", "/admin/v1/functions", "Ctrl::index"),
            route_tuple("GET", "/admin/v1/multi", "closure"),
            route_tuple("GET", "/admin/v1/after-multi", "Ctrl::after"),
            route_tuple("GET", "/admin/guarded", "GuardController::index"),
            route_tuple("GET", "/admin/controlled", "Ctrl::controlled"),
            route_tuple("GET", "/admin/sibling", "SiblingController::index"),
        ]);
        for route in [
            route_tuple("GET", "/admin/v1/photos", "PhotoController::index"),
            route_tuple("GET", "/admin/v1/photos/create", "PhotoController::create"),
            route_tuple("POST", "/admin/v1/photos", "PhotoController::store"),
            route_tuple("GET", "/admin/v1/photos/{photo}", "PhotoController::show"),
            route_tuple("GET", "/admin/v1/photos/{photo}/edit", "PhotoController::edit"),
            route_tuple("PUT", "/admin/v1/photos/{photo}", "PhotoController::update"),
            route_tuple("DELETE", "/admin/v1/photos/{photo}", "PhotoController::destroy"),
        ] {
            expected.insert(route);
        }
        for route in [
            route_tuple("GET", "/admin/v1/events", "EventController::index"),
            route_tuple("POST", "/admin/v1/events", "EventController::store"),
            route_tuple("GET", "/admin/v1/events/{event}", "EventController::show"),
            route_tuple("PUT", "/admin/v1/events/{event}", "EventController::update"),
            route_tuple("DELETE", "/admin/v1/events/{event}", "EventController::destroy"),
        ] {
            expected.insert(route);
        }
        assert_eq!(route_set(&scan), expected);
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
        assert_eq!(
            language_for_path(Path::new("Main.cs"), enabled),
            Some(LanguageKind::CSharp)
        );
        assert_eq!(language_for_path(Path::new("main.rb"), disabled), None);
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
            ("a.cs", "demo::a"),
            ("a.rb", "demo::a"),
            ("a.swift", "demo::a"),
            ("a.php", "demo::a"),
            ("a.tsx", "demo::a"),
            ("b.jsx", "demo::b"),
            ("c.cxx.ts", "demo::c.cxx"),
            ("foo.h.ts", "demo::foo.h"),
            ("x.cs.ts", "demo::x.cs"),
            ("x.rb.mjs", "demo::x.rb"),
            ("y.php.js", "demo::y.php"),
            ("z.swift.ts", "demo::z.swift"),
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
        let comparison_chain = format!(
            "bool ordered = {};",
            std::iter::repeat_n("left < right", POLYGLOT_AST_MAX_DEPTH + 100)
                .collect::<Vec<_>>()
                .join(" && ")
        );
        assert!(
            max_source_delimiter_depth(&comparison_chain, POLYGLOT_AST_MAX_DEPTH, LanguageKind::Cpp)
                < POLYGLOT_AST_MAX_DEPTH
        );
        let grouped_comparisons = format!(
            "bool ordered = ({}) && ({});",
            std::iter::repeat_n("a<b", POLYGLOT_AST_MAX_DEPTH + 100)
                .collect::<Vec<_>>()
                .join(" && "),
            std::iter::repeat_n("c>d", POLYGLOT_AST_MAX_DEPTH + 100)
                .collect::<Vec<_>>()
                .join(" && ")
        );
        assert!(
            max_source_delimiter_depth(&grouped_comparisons, POLYGLOT_AST_MAX_DEPTH, LanguageKind::Cpp)
                < POLYGLOT_AST_MAX_DEPTH
        );
        let multiline_templates = format!(
            "{}int{};",
            "box<\n".repeat(POLYGLOT_AST_MAX_DEPTH + 100),
            ">\n".repeat(POLYGLOT_AST_MAX_DEPTH + 100)
        );
        assert!(
            max_source_delimiter_depth(&multiline_templates, POLYGLOT_AST_MAX_DEPTH, LanguageKind::Cpp)
                > POLYGLOT_AST_MAX_DEPTH,
            "nested C++ templates must be rejected before native parsing"
        );
        let exact_template_boundary = format!(
            "{}int{};",
            "box<".repeat(POLYGLOT_AST_MAX_DEPTH),
            ">".repeat(POLYGLOT_AST_MAX_DEPTH)
        );
        assert_eq!(
            max_source_delimiter_depth(&exact_template_boundary, POLYGLOT_AST_MAX_DEPTH, LanguageKind::Cpp,),
            POLYGLOT_AST_MAX_DEPTH
        );
        let java_wildcard_storm = format!(
            "class Deep {{ {}String{} value; }}",
            "java.util.List<? extends ".repeat(POLYGLOT_AST_MAX_DEPTH + 1),
            ">".repeat(POLYGLOT_AST_MAX_DEPTH + 1)
        );
        assert!(
            max_source_delimiter_depth(&java_wildcard_storm, POLYGLOT_AST_MAX_DEPTH, LanguageKind::Java)
                > POLYGLOT_AST_MAX_DEPTH
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
        std::fs::write(tmp.path().join("build/generated.cs"), "class GeneratedCs {}\n").expect("generated cs");
        std::fs::write(tmp.path().join("vendor/library.rb"), "class VendoredRuby; end\n").expect("vendor rb");
        std::fs::write(
            tmp.path().join("third_party/library.swift"),
            "class ThirdPartySwift {}\n",
        )
        .expect("third party swift");
        std::fs::write(tmp.path().join("build/generated.php"), "<?php class GeneratedPhp {}\n").expect("generated php");

        let scan = run_repo_scan_at(tmp.path()).expect("scan");
        assert_eq!(scan.files.len(), 1);
        assert_eq!(scan.files[0].rel_path, "src/app.c");
        assert!(scan.symbols.iter().any(|symbol| symbol.name == "source_fn"));
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v3_pathological_all_v3_languages_are_skipped_before_parse() {
        let _env = EnvVarGuard::set(POLYGLOT_V3_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        for (name, prefix) in [
            ("Deep.java", "class Deep { void run() {\n"),
            ("deep.c", "int run(void) {\n"),
            ("deep.cpp", "template <typename T> int run() {\n"),
            ("Deep.cs", "class Deep { void Run() {\n"),
            ("deep.rb", "def run\n"),
            ("Deep.swift", "class Deep { func run() {\n"),
            ("deep.php", "<?php function run() {\n"),
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
            ("Huge.cs", POLYGLOT_CSHARP_MAX_BYTES),
            ("huge.rb", POLYGLOT_RUBY_MAX_BYTES),
            ("Huge.swift", POLYGLOT_SWIFT_MAX_BYTES),
            ("huge.php", POLYGLOT_PHP_MAX_BYTES),
        ] {
            std::fs::write(tmp.path().join(name), vec![b' '; max_bytes + 1]).expect("huge source");
        }
        for (name, max_line_bytes) in [
            ("LongLine.java", POLYGLOT_JAVA_MAX_LINE_BYTES),
            ("long_line.c", POLYGLOT_C_MAX_LINE_BYTES),
            ("long_line.cpp", POLYGLOT_CPP_MAX_LINE_BYTES),
            ("LongLine.cs", POLYGLOT_CSHARP_MAX_LINE_BYTES),
            ("long_line.rb", POLYGLOT_RUBY_MAX_LINE_BYTES),
            ("LongLine.swift", POLYGLOT_SWIFT_MAX_LINE_BYTES),
            ("long_line.php", POLYGLOT_PHP_MAX_LINE_BYTES),
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
                ("Deep.cs".to_string(), "max_delimiter_depth".to_string()),
                ("Deep.swift".to_string(), "max_delimiter_depth".to_string()),
                ("Huge.java".to_string(), "max_bytes".to_string()),
                ("Huge.cs".to_string(), "max_bytes".to_string()),
                ("Huge.swift".to_string(), "max_bytes".to_string()),
                ("LongLine.java".to_string(), "max_line_bytes".to_string()),
                ("LongLine.cs".to_string(), "max_line_bytes".to_string()),
                ("LongLine.swift".to_string(), "max_line_bytes".to_string()),
                ("deep.c".to_string(), "max_delimiter_depth".to_string()),
                ("deep.cpp".to_string(), "max_delimiter_depth".to_string()),
                ("deep.php".to_string(), "max_delimiter_depth".to_string()),
                ("deep.rb".to_string(), "max_delimiter_depth".to_string()),
                ("huge.c".to_string(), "max_bytes".to_string()),
                ("huge.cpp".to_string(), "max_bytes".to_string()),
                ("huge.php".to_string(), "max_bytes".to_string()),
                ("huge.rb".to_string(), "max_bytes".to_string()),
                ("long_line.c".to_string(), "max_line_bytes".to_string()),
                ("long_line.cpp".to_string(), "max_line_bytes".to_string()),
                ("long_line.php".to_string(), "max_line_bytes".to_string()),
                ("long_line.rb".to_string(), "max_line_bytes".to_string()),
                ("template_storm.cpp".to_string(), "max_delimiter_depth".to_string()),
            ])
        );
    }

    #[cfg(unix)]
    #[test]
    #[serial_test::serial]
    fn polyglot_v3_symlink_to_device_is_rejected_without_reading() {
        let _env = EnvVarGuard::set(POLYGLOT_V3_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        std::os::unix::fs::symlink("/dev/zero", tmp.path().join("zero.c")).expect("device symlink");

        let error = run_repo_scan_at(tmp.path()).expect_err("symlink must fail closed");
        assert!(error.to_string().contains("rejects symlink"));
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
    fn baseline_ts_skip_diagnostics_survive_rust_hybrid_merge() {
        let _v2 = EnvVarGuard::unset(POLYGLOT_V2_ENV);
        let _v3 = EnvVarGuard::unset(POLYGLOT_V3_ENV);
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
        std::fs::write(tmp.path().join("deep.ts"), deep_call_source(POLYGLOT_AST_MAX_DEPTH + 1))
            .expect("deep TypeScript");

        let scan = run_repo_scan_at(tmp.path()).expect("hybrid scan");
        assert!(scan.files.iter().any(|file| file.rel_path == "mini/src/lib.rs"));
        assert_eq!(
            scan.diagnostics.v3_skipped_files,
            vec![V3SkippedFile {
                rel_path: "deep.ts".to_string(),
                reason: "max_delimiter_depth".to_string(),
            }]
        );
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v3_django_urlpatterns_include_and_handlers_are_precise() {
        let _v2 = EnvVarGuard::unset(POLYGLOT_V2_ENV);
        let _v3 = EnvVarGuard::set(POLYGLOT_V3_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(tmp.path().join("blog")).expect("blog dir");
        std::fs::write(
            tmp.path().join("urls.py"),
            r#"from django.urls import include, path, re_path
from . import views

urlpatterns = [
    path("health/", views.health),
    re_path(r"^legacy/(?P<id>\d+)/$", views.legacy),
    path("detail/", DetailView.as_view()),
    path("api/", include("blog.urls")),
    path("missing/", include("missing.urls")),
]
"#,
        )
        .expect("root urls");
        std::fs::write(
            tmp.path().join("views.py"),
            "def health():\n    pass\ndef legacy():\n    pass\nclass DetailView:\n    pass\n",
        )
        .expect("root views");
        std::fs::write(
            tmp.path().join("blog/urls.py"),
            r#"from django.urls import path
from django.conf.urls import url
from . import views

urlpatterns = [
    path("posts/", views.posts),
    url(r"^old/$", views.old),
]
"#,
        )
        .expect("blog urls");
        std::fs::write(
            tmp.path().join("blog/views.py"),
            "def posts():\n    pass\ndef old():\n    pass\n",
        )
        .expect("blog views");

        let scan = run_repo_scan_at(tmp.path()).expect("scan");
        assert_eq!(
            framework_route_set(&scan),
            BTreeSet::from([
                framework_route_tuple("ANY", "health/", "views.health", "django"),
                framework_route_tuple("ANY", r"^legacy/(?P<id>\d+)/$", "views.legacy", "django"),
                framework_route_tuple("ANY", "detail/", "DetailView.as_view()", "django"),
                framework_route_tuple("ANY", "api/posts/", "views.posts", "django"),
                framework_route_tuple("ANY", "api/old/$", "views.old", "django"),
            ])
        );
        assert!(scan
            .routes
            .iter()
            .any(|route| { route.path == "api/posts/" && route.handler_file.as_deref() == Some("blog/views.py") }));
        assert_eq!(scan.diagnostics.unresolved_routes.len(), 1);
        let unresolved = &scan.diagnostics.unresolved_routes[0];
        assert_eq!(unresolved.reason, "include_not_found");
        assert_eq!(unresolved.path, "missing/");
        assert_eq!(unresolved.handler_fn, "include(\"missing.urls\")");
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v3_django_ambiguous_include_claims_all_matching_urlconfs() {
        let _v3 = EnvVarGuard::set(POLYGLOT_V3_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        for directory in ["project", "one/shared", "two/shared"] {
            std::fs::create_dir_all(tmp.path().join(directory)).expect("urlconf dir");
        }
        std::fs::write(
            tmp.path().join("project/settings.py"),
            "ROOT_URLCONF = 'project.urls'\n",
        )
        .expect("settings");
        std::fs::write(
            tmp.path().join("project/urls.py"),
            "from django.urls import include, path\nurlpatterns = [path('shared/', include('shared.urls'))]\n",
        )
        .expect("project urls");
        for (directory, path) in [("one/shared", "one/"), ("two/shared", "two/")] {
            std::fs::write(
                tmp.path().join(directory).join("urls.py"),
                format!("from django.urls import path\nurlpatterns = [path('{path}', views.child)]\n"),
            )
            .expect("ambiguous child urls");
        }

        let scan = run_repo_scan_at(tmp.path()).expect("scan");
        assert!(framework_route_set(&scan).is_empty());
        assert_eq!(scan.diagnostics.unresolved_routes.len(), 1);
        assert_eq!(scan.diagnostics.unresolved_routes[0].reason, "include_ambiguous");
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v3_django_identifier_include_is_diagnostic_not_child_root() {
        let _v3 = EnvVarGuard::set(POLYGLOT_V3_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        for directory in ["project", "blog"] {
            std::fs::create_dir_all(tmp.path().join(directory)).expect("urlconf dir");
        }
        std::fs::write(
            tmp.path().join("project/settings.py"),
            "ROOT_URLCONF = 'project.urls'\n",
        )
        .expect("settings");
        std::fs::write(
            tmp.path().join("project/urls.py"),
            "from django.urls import include, path\nfrom blog import urls as blog_urls\nurlpatterns = [path('blog/', include(blog_urls))]\n",
        )
        .expect("project urls");
        std::fs::write(
            tmp.path().join("blog/urls.py"),
            "from django.urls import path\nurlpatterns = [path('posts/', views.posts)]\n",
        )
        .expect("blog urls");

        let scan = run_repo_scan_at(tmp.path()).expect("scan");
        assert!(framework_route_set(&scan).is_empty());
        assert_eq!(scan.diagnostics.unresolved_routes.len(), 1);
        assert_eq!(scan.diagnostics.unresolved_routes[0].reason, "include_dynamic");
        assert_eq!(scan.diagnostics.unresolved_routes[0].handler_fn, "include(blog_urls)");
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v3_django_branching_expansion_is_output_bounded() {
        let _v3 = EnvVarGuard::set(POLYGLOT_V3_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        write_branching_django_fixture(tmp.path(), 10);
        let canonical = tmp.path().canonicalize().expect("canonical");
        let policy = crate::repo_scan_policy::RepoScanPolicy::for_test_roots(
            vec![canonical.clone()],
            crate::repo_scan_policy::RepoScanLimits {
                max_depth: 16,
                max_files: 64,
                max_bytes: 1024 * 1024,
                max_file_bytes: 128 * 1024,
                timeout: std::time::Duration::from_secs(5),
                ..crate::repo_scan_policy::RepoScanLimits::default()
            },
        );

        let error = run_repo_scan_at_with_policy(&canonical, &policy).expect_err("branching expansion must be capped");
        assert!(error.to_string().contains("Django route expansion"));
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v3_django_branching_below_expansion_cap_succeeds() {
        let _v3 = EnvVarGuard::set(POLYGLOT_V3_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        write_branching_django_fixture(tmp.path(), 9);

        let scan = run_repo_scan_at(tmp.path()).expect("bounded branching scan");
        assert_eq!(scan.routes.len(), 512);
        assert!(scan
            .routes
            .iter()
            .all(|route| route.framework.as_deref() == Some("django")));
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v3_django_include_cycle_is_path_local_and_finite() {
        let _v3 = EnvVarGuard::set(POLYGLOT_V3_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        for directory in ["project", "app"] {
            std::fs::create_dir_all(tmp.path().join(directory)).expect("urlconf dir");
        }
        std::fs::write(
            tmp.path().join("project/settings.py"),
            "ROOT_URLCONF = 'project.urls'\n",
        )
        .expect("settings");
        std::fs::write(
            tmp.path().join("project/urls.py"),
            "from django.urls import include, path\nurlpatterns = [path('home/', views.home), path('app/', include('app.urls'))]\n",
        )
        .expect("project urls");
        std::fs::write(
            tmp.path().join("app/urls.py"),
            "from django.urls import include, path\nurlpatterns = [path('child/', views.child), path('back/', include('project.urls'))]\n",
        )
        .expect("app urls");

        let scan = run_repo_scan_at(tmp.path()).expect("cycle-safe scan");
        let django_routes: Vec<_> = scan
            .routes
            .iter()
            .filter(|route| route.framework.as_deref() == Some("django"))
            .collect();
        assert_eq!(django_routes.len(), 2);
        assert!(django_routes.iter().any(|route| route.path == "home/"));
        assert!(django_routes.iter().any(|route| route.path == "app/child/"));
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v3_django_include_chain_respects_depth_limit() {
        let _v3 = EnvVarGuard::set(POLYGLOT_V3_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(tmp.path().join("project")).expect("project");
        std::fs::write(
            tmp.path().join("project/settings.py"),
            "ROOT_URLCONF = 'project.urls'\n",
        )
        .expect("settings");
        std::fs::write(
            tmp.path().join("project/urls.py"),
            "from django.urls import include, path\nurlpatterns = [path('next/', include('level1.urls'))]\n",
        )
        .expect("root urls");
        for level in 1..=6 {
            let directory = tmp.path().join(format!("level{level}"));
            std::fs::create_dir_all(&directory).expect("level dir");
            let source = if level == 6 {
                "from django.urls import path\nurlpatterns = [path('leaf/', views.leaf)]\n".to_string()
            } else {
                format!(
                    "from django.urls import include, path\nurlpatterns = [path('next/', include('level{}.urls'))]\n",
                    level + 1
                )
            };
            std::fs::write(directory.join("urls.py"), source).expect("level urls");
        }
        let canonical = tmp.path().canonicalize().expect("canonical");
        let policy = crate::repo_scan_policy::RepoScanPolicy::for_test_roots(
            vec![canonical.clone()],
            crate::repo_scan_policy::RepoScanLimits {
                max_depth: 3,
                max_files: 128,
                max_bytes: 1024 * 1024,
                max_file_bytes: 128 * 1024,
                timeout: std::time::Duration::from_secs(5),
                ..crate::repo_scan_policy::RepoScanLimits::default()
            },
        );

        let error = run_repo_scan_at_with_policy(&canonical, &policy).expect_err("deep include chain must fail");
        assert!(error.to_string().contains("directory depth 3"));
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v3_spring_controller_mappings_and_arrays_are_precise() {
        let _v3 = EnvVarGuard::set(POLYGLOT_V3_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("UsersController.java"),
            r#"import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(path = {"/api", "/admin"})
public class UsersController {
    @GetMapping(value = {"/users", "/people"})
    public void list() {}

    @PostMapping(path = "/users")
    public void create() {}

    @RequestMapping(path = "/search", method = RequestMethod.GET)
    public void search() {}

    @RequestMapping(value = "/multi", method = {RequestMethod.GET, RequestMethod.POST})
    public void multi() {}

    @RequestMapping
    public void root() {}

    @GetMapping
    public void noPath() {}

    @GetMapping(ApiPaths.USERS)
    public void dynamicPath() {}
}

class LibraryOnly {
    @GetMapping("/phantom")
    public void helper() {}
}
"#,
        )
        .expect("controller");

        let scan = run_repo_scan_at(tmp.path()).expect("scan");
        let mut expected = BTreeSet::new();
        for prefix in ["/api", "/admin"] {
            for path in ["/users", "/people"] {
                expected.insert(framework_route_tuple(
                    "GET",
                    &format!("{prefix}{path}"),
                    "UsersController.list",
                    "spring",
                ));
            }
            expected.insert(framework_route_tuple(
                "POST",
                &format!("{prefix}/users"),
                "UsersController.create",
                "spring",
            ));
            expected.insert(framework_route_tuple(
                "GET",
                &format!("{prefix}/search"),
                "UsersController.search",
                "spring",
            ));
            for method in ["GET", "POST"] {
                expected.insert(framework_route_tuple(
                    method,
                    &format!("{prefix}/multi"),
                    "UsersController.multi",
                    "spring",
                ));
            }
            expected.insert(framework_route_tuple("ANY", prefix, "UsersController.root", "spring"));
            expected.insert(framework_route_tuple("GET", prefix, "UsersController.noPath", "spring"));
        }
        assert_eq!(framework_route_set(&scan), expected);
        assert!(scan.routes.iter().all(|route| route.path != "/phantom"));
        assert!(scan.routes.iter().all(|route| {
            route.framework.as_deref() != Some("spring")
                || route.handler_file.as_deref() == Some("UsersController.java")
        }));
        let dynamic = scan
            .diagnostics
            .unresolved_routes
            .iter()
            .find(|route| route.handler_fn == "UsersController.dynamicPath")
            .expect("dynamic Spring annotation diagnostic");
        assert_eq!(dynamic.method, "GET");
        assert_eq!(dynamic.reason, "annotation_dynamic");
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v3_spring_test_source_controllers_are_suppressed() {
        let _v3 = EnvVarGuard::set(POLYGLOT_V3_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        let test_dir = tmp.path().join("src/test/java/com/acme");
        std::fs::create_dir_all(&test_dir).expect("test source dir");
        std::fs::write(
            test_dir.join("TestController.java"),
            r#"@RestController
class TestController {
    @GetMapping("/test-only")
    void testOnly() {}
}
"#,
        )
        .expect("test controller");

        let scan = run_repo_scan_at(tmp.path()).expect("scan");
        assert!(scan.routes.is_empty());
        assert!(scan
            .files
            .iter()
            .find(|file| file.rel_path.ends_with("TestController.java"))
            .is_some_and(|file| file.is_test_file));
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v3_nextjs_file_routes_are_dependency_gated_and_precise() {
        let _v2 = EnvVarGuard::unset(POLYGLOT_V2_ENV);
        let _v3 = EnvVarGuard::set(POLYGLOT_V3_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("package.json"),
            r#"{"name":"next-fixture","dependencies":{"next":"15.0.0"}}"#,
        )
        .expect("package");
        for directory in [
            "pages/blog",
            "pages/api",
            "app/(marketing)/about",
            "app/dashboard",
            "app/api/items",
            "app/@analytics",
            "app/feed/(.)photo",
            "app/archive/(..)(..)photo",
            "app/pages/[slug]",
            "src/components/pages",
            "components",
        ] {
            std::fs::create_dir_all(tmp.path().join(directory)).expect("route dir");
        }
        for (path, source) in [
            ("pages/index.tsx", "export default function Home() { return null; }\n"),
            (
                "pages/blog/[slug].tsx",
                "export default function Blog() { return null; }\n",
            ),
            ("pages/_app.tsx", "export default function App() { return null; }\n"),
            (
                "pages/api/users.ts",
                "export function GET() {}\nexport const POST = () => {};\n",
            ),
            ("pages/api/_internal.ts", "export function GET() {}\n"),
            (
                "app/(marketing)/about/page.tsx",
                "export default function About() { return null; }\n",
            ),
            (
                "app/dashboard/page.jsx",
                "export default function Dashboard() { return null; }\n",
            ),
            (
                "app/api/items/route.ts",
                "export async function GET() {}\nexport const POST = () => {};\n",
            ),
            ("app/@analytics/page.tsx", "export default function Analytics() {}\n"),
            ("app/feed/(.)photo/page.tsx", "export default function Photo() {}\n"),
            (
                "app/archive/(..)(..)photo/page.tsx",
                "export default function ArchivePhoto() {}\n",
            ),
            ("app/pages/[slug]/page.tsx", "export default function NestedPage() {}\n"),
            ("src/components/pages/Card.tsx", "export function Card() {}\n"),
            (
                "components/client.ts",
                "fetch('/client-only');\naxios.get('/api/not-a-server-route');\n",
            ),
        ] {
            std::fs::write(tmp.path().join(path), source).expect("fixture source");
        }

        let scan = run_repo_scan_at(tmp.path()).expect("scan");
        assert_eq!(
            framework_route_set(&scan),
            BTreeSet::from([
                framework_route_tuple("ANY", "/", "pages/index.tsx", "nextjs"),
                framework_route_tuple("ANY", "/blog/[slug]", "pages/blog/[slug].tsx", "nextjs"),
                framework_route_tuple("GET", "/api/users", "pages/api/users.ts", "nextjs"),
                framework_route_tuple("POST", "/api/users", "pages/api/users.ts", "nextjs"),
                framework_route_tuple("ANY", "/about", "app/(marketing)/about/page.tsx", "nextjs"),
                framework_route_tuple("ANY", "/dashboard", "app/dashboard/page.jsx", "nextjs"),
                framework_route_tuple("GET", "/api/items", "app/api/items/route.ts", "nextjs"),
                framework_route_tuple("POST", "/api/items", "app/api/items/route.ts", "nextjs"),
                framework_route_tuple("ANY", "/", "app/@analytics/page.tsx", "nextjs"),
                framework_route_tuple("ANY", "/feed/photo", "app/feed/(.)photo/page.tsx", "nextjs"),
                framework_route_tuple("ANY", "/archive/photo", "app/archive/(..)(..)photo/page.tsx", "nextjs",),
                framework_route_tuple("ANY", "/pages/[slug]", "app/pages/[slug]/page.tsx", "nextjs",),
            ])
        );
        assert!(scan.routes.iter().all(|route| !route.path.contains("client-only")));
        assert!(scan
            .routes
            .iter()
            .all(|route| !route.path.contains("not-a-server-route")));
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v3_nuxt_file_routes_are_precise() {
        let _v3 = EnvVarGuard::set(POLYGLOT_V3_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("package.json"), r#"{"dependencies":{"nuxt":"4.0.0"}}"#).expect("package");
        std::fs::create_dir_all(tmp.path().join("pages/users")).expect("pages");
        std::fs::create_dir_all(tmp.path().join("src/components/pages")).expect("components");
        std::fs::write(tmp.path().join("pages/index.vue"), "<template>home</template>\n").expect("index");
        std::fs::write(tmp.path().join("pages/users/[id].vue"), "<template>user</template>\n").expect("user");
        std::fs::write(
            tmp.path().join("src/components/pages/Card.vue"),
            "<template>not a route</template>\n",
        )
        .expect("component");

        let scan = run_repo_scan_at(tmp.path()).expect("scan");
        assert_eq!(
            framework_route_set(&scan),
            BTreeSet::from([
                framework_route_tuple("ANY", "/", "pages/index.vue", "nuxt"),
                framework_route_tuple("ANY", "/users/[id]", "pages/users/[id].vue", "nuxt"),
            ])
        );
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v3_sveltekit_file_routes_and_exported_verbs_are_precise() {
        let _v3 = EnvVarGuard::set(POLYGLOT_V3_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("package.json"),
            r#"{"devDependencies":{"@sveltejs/kit":"2.0.0"}}"#,
        )
        .expect("package");
        for directory in [
            "src/routes",
            "src/routes/blog/[slug]",
            "src/routes/api/items",
            "src/routes/(app)/dashboard",
            "src/routes/(api)/grouped",
        ] {
            std::fs::create_dir_all(tmp.path().join(directory)).expect("route dir");
        }
        std::fs::write(tmp.path().join("src/routes/+page.svelte"), "<h1>Home</h1>\n").expect("root page");
        std::fs::write(
            tmp.path().join("src/routes/blog/[slug]/+page.svelte"),
            "<h1>Blog</h1>\n",
        )
        .expect("blog page");
        std::fs::write(
            tmp.path().join("src/routes/api/items/+server.ts"),
            "export function GET() {}\nexport const DELETE = () => {};\n",
        )
        .expect("server");
        std::fs::write(
            tmp.path().join("src/routes/(app)/dashboard/+page.svelte"),
            "<h1>Dashboard</h1>\n",
        )
        .expect("grouped page");
        std::fs::write(
            tmp.path().join("src/routes/(api)/grouped/+server.ts"),
            "export function POST() {}\n",
        )
        .expect("grouped server");

        let scan = run_repo_scan_at(tmp.path()).expect("scan");
        assert_eq!(
            framework_route_set(&scan),
            BTreeSet::from([
                framework_route_tuple("ANY", "/", "src/routes/+page.svelte", "sveltekit"),
                framework_route_tuple(
                    "ANY",
                    "/blog/[slug]",
                    "src/routes/blog/[slug]/+page.svelte",
                    "sveltekit",
                ),
                framework_route_tuple("GET", "/api/items", "src/routes/api/items/+server.ts", "sveltekit"),
                framework_route_tuple("DELETE", "/api/items", "src/routes/api/items/+server.ts", "sveltekit",),
                framework_route_tuple(
                    "ANY",
                    "/dashboard",
                    "src/routes/(app)/dashboard/+page.svelte",
                    "sveltekit",
                ),
                framework_route_tuple("POST", "/grouped", "src/routes/(api)/grouped/+server.ts", "sveltekit",),
            ])
        );
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v3_file_routes_require_framework_dependency() {
        let _v3 = EnvVarGuard::set(POLYGLOT_V3_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("package.json"),
            r#"{"dependencies":{"react":"19.0.0"}}"#,
        )
        .expect("package");
        std::fs::create_dir_all(tmp.path().join("pages")).expect("pages");
        std::fs::write(
            tmp.path().join("pages/index.tsx"),
            "export default function Page() {}\n",
        )
        .expect("page");
        let scan = run_repo_scan_at(tmp.path()).expect("scan");
        assert!(framework_route_set(&scan).is_empty());
        assert!(scan.routes.is_empty());
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v3_nested_package_without_framework_shadows_parent_scope() {
        let _v3 = EnvVarGuard::set(POLYGLOT_V3_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("package.json"), r#"{"dependencies":{"next":"15.0.0"}}"#).expect("root package");
        std::fs::create_dir_all(tmp.path().join("pages")).expect("root pages");
        std::fs::write(
            tmp.path().join("pages/index.tsx"),
            "export default function Home() {}\n",
        )
        .expect("home");
        std::fs::create_dir_all(tmp.path().join("docs/pages")).expect("docs pages");
        std::fs::write(
            tmp.path().join("docs/package.json"),
            r#"{"dependencies":{"react":"19.0.0"}}"#,
        )
        .expect("docs package");
        std::fs::write(
            tmp.path().join("docs/pages/intro.tsx"),
            "export default function Intro() {}\n",
        )
        .expect("intro");

        let scan = run_repo_scan_at(tmp.path()).expect("scan");
        assert_eq!(
            framework_route_set(&scan),
            BTreeSet::from([framework_route_tuple("ANY", "/", "pages/index.tsx", "nextjs")])
        );
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v3_dark_route_trees_unset_and_zero_are_byte_identical() {
        let _v2 = EnvVarGuard::unset(POLYGLOT_V2_ENV);
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("package.json"),
            r#"{"dependencies":{"next":"15","nuxt":"4","@sveltejs/kit":"2"}}"#,
        )
        .expect("package");
        for directory in ["pages", "app/api", "src/routes", "django", "spring"] {
            std::fs::create_dir_all(tmp.path().join(directory)).expect("dark dir");
        }
        std::fs::write(
            tmp.path().join("pages/index.tsx"),
            "export default function Page() {}\n",
        )
        .expect("next");
        std::fs::write(tmp.path().join("pages/nuxt.vue"), "<template>dark</template>\n").expect("nuxt");
        std::fs::write(tmp.path().join("app/api/route.ts"), "export function GET() {}\n").expect("app");
        std::fs::write(tmp.path().join("src/routes/+page.svelte"), "<p>dark</p>\n").expect("svelte");
        std::fs::write(
            tmp.path().join("django/urls.py"),
            "from django.urls import path\nurlpatterns = [path('x/', views.x)]\n",
        )
        .expect("django");
        std::fs::write(
            tmp.path().join("spring/DarkController.java"),
            "@RestController class DarkController { @GetMapping(\"/x\") void x() {} }\n",
        )
        .expect("spring");

        let unset = {
            let _v3 = EnvVarGuard::unset(POLYGLOT_V3_ENV);
            stable_scan_json(run_repo_scan_at(tmp.path()).expect("unset scan"))
        };
        let zero = {
            let _v3 = EnvVarGuard::set(POLYGLOT_V3_ENV, "0");
            stable_scan_json(run_repo_scan_at(tmp.path()).expect("zero scan"))
        };
        assert_eq!(unset.as_bytes(), zero.as_bytes());
        assert!(!unset.contains("nextjs"));
        assert!(!unset.contains("\"framework\":\"django\""));
        assert!(!unset.contains("\"framework\":\"spring\""));
        assert!(!unset.contains(POLYGLOT_V3_ENV));
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
        std::fs::create_dir_all(tmp.path().join("config")).expect("config");
        std::fs::create_dir_all(tmp.path().join("routes")).expect("routes");
        std::fs::write(
            tmp.path().join("config/routes.rb"),
            "get \"/dark-rails\" => \"dark#show\"\n",
        )
        .expect("dark rails route");
        std::fs::write(
            tmp.path().join("routes/api.php"),
            "<?php Route::get('/dark-laravel', function () {});\n",
        )
        .expect("dark laravel route");

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
            "Dark.cs",
            "dark.rb",
            "Dark.swift",
            "dark.php",
        ] {
            assert!(!unset.contains(name), "dark payload leaked {name}");
        }
        assert!(unset.contains("foo.h.ts"));
        assert!(!unset.contains(POLYGLOT_V3_ENV));
        assert!(!unset.contains("v3_skipped_files"));
        assert!(!unset.contains("dark-rails"));
        assert!(!unset.contains("dark-laravel"));
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
        std::fs::create_dir_all(tmp.path().join("config")).expect("config");
        std::fs::create_dir_all(tmp.path().join("routes")).expect("routes");
        std::fs::write(
            tmp.path().join("config/routes.rb"),
            "get \"/dark-v2-rails\" => \"dark#show\"\n",
        )
        .expect("dark V2 rails route");
        std::fs::write(
            tmp.path().join("routes/api.php"),
            "<?php Route::get('/dark-v2-laravel', function () {});\n",
        )
        .expect("dark V2 laravel route");
        let after = stable_scan_json(run_repo_scan_at(tmp.path()).expect("V2 plus dark V3"));

        assert_eq!(before.as_bytes(), after.as_bytes());
        assert!(after.contains("app.js"));
        assert!(after.contains("main.go"));
        assert!(after.contains("foo.h.ts"));
        assert!(!after.contains("v3_skipped_files"));
        assert!(!after.contains("dark-v2-rails"));
        assert!(!after.contains("dark-v2-laravel"));
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
    fn ts_deep_source_is_skipped_before_native_parse() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("package.json"), r#"{"name":"deep-ts"}"#).expect("package");
        let deep_src = deep_call_source(POLYGLOT_AST_MAX_DEPTH + 256);
        std::fs::write(tmp.path().join("deep.ts"), &deep_src).expect("deep ts");
        let scan = run_polyglot_scan_at(tmp.path()).expect("scan");
        assert!(scan.files.is_empty());
        assert_eq!(
            scan.diagnostics.v3_skipped_files,
            vec![V3SkippedFile {
                rel_path: "deep.ts".to_string(),
                reason: "max_delimiter_depth".to_string(),
            }]
        );

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
        .expect("deep TypeScript admission");
        assert!(extracted.is_none());
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
    fn polyglot_v2_deep_js_is_skipped_before_native_parse() {
        let _env = EnvVarGuard::set(POLYGLOT_V2_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("package.json"), r#"{"name":"deep-js"}"#).expect("package");
        let src = deep_call_source(POLYGLOT_AST_MAX_DEPTH + 256);
        assert!(src.len() < POLYGLOT_JS_MAX_BYTES);
        assert!(src.lines().map(str::len).max().unwrap_or(0) < POLYGLOT_JS_MAX_LINE_BYTES);
        std::fs::write(tmp.path().join("app.js"), &src).expect("js");

        let scan = run_repo_scan_at(tmp.path()).expect("scan");
        assert!(scan.files.is_empty());
        assert_eq!(
            scan.diagnostics.v3_skipped_files,
            vec![V3SkippedFile {
                rel_path: "app.js".to_string(),
                reason: "max_delimiter_depth".to_string(),
            }]
        );

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
        .expect("deep multiline JS admission");
        assert!(extracted.is_none());
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

        assert!(!should_use_rust_workspace_scan(tmp.path()).expect("scan mode"));
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

        assert!(!should_use_rust_workspace_scan(tmp.path()).expect("scan mode"));
        assert!(has_rust_workspace(tmp.path()).expect("rust workspace"));

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

    // ---------------------------------------------------------------------
    // Language selection and skip rules
    // ---------------------------------------------------------------------

    fn options(v2: bool, v3: bool) -> PolyglotScanOptions {
        PolyglotScanOptions {
            v2_enabled: v2,
            v3_enabled: v3,
        }
    }

    #[test]
    fn language_for_path_is_gated_by_the_v2_and_v3_flags() {
        let base = options(false, false);
        for (name, expected) in [
            ("a.rs", Some(LanguageKind::Rust)),
            ("a.ts", Some(LanguageKind::TypeScript)),
            ("a.tsx", Some(LanguageKind::Tsx)),
            ("a.py", Some(LanguageKind::Python)),
            ("a.vue", Some(LanguageKind::Vue)),
            ("a.js", None),
            ("a.jsx", None),
            ("a.go", None),
            ("a.java", None),
            ("a.svelte", None),
            ("a.txt", None),
            ("noextension", None),
        ] {
            assert_eq!(language_for_path(Path::new(name), base), expected, "{name}");
        }

        let v2 = options(true, false);
        for (name, expected) in [
            ("a.js", Some(LanguageKind::TypeScript)),
            ("a.mjs", Some(LanguageKind::TypeScript)),
            ("a.cjs", Some(LanguageKind::TypeScript)),
            ("a.jsx", Some(LanguageKind::Tsx)),
            ("a.go", Some(LanguageKind::Go)),
            ("a.java", None),
            ("a.svelte", None),
        ] {
            assert_eq!(language_for_path(Path::new(name), v2), expected, "v2 {name}");
        }

        let v3 = options(false, true);
        for (name, expected) in [
            ("a.svelte", Some(LanguageKind::Svelte)),
            ("a.java", Some(LanguageKind::Java)),
            ("a.c", Some(LanguageKind::C)),
            ("a.h", Some(LanguageKind::C)),
            ("a.cpp", Some(LanguageKind::Cpp)),
            ("a.cc", Some(LanguageKind::Cpp)),
            ("a.cxx", Some(LanguageKind::Cpp)),
            ("a.hpp", Some(LanguageKind::Cpp)),
            ("a.hh", Some(LanguageKind::Cpp)),
            ("a.hxx", Some(LanguageKind::Cpp)),
            ("a.cs", Some(LanguageKind::CSharp)),
            ("a.rb", Some(LanguageKind::Ruby)),
            ("a.swift", Some(LanguageKind::Swift)),
            ("a.php", Some(LanguageKind::Php)),
            ("a.js", Some(LanguageKind::TypeScript)),
            ("a.go", None),
        ] {
            assert_eq!(language_for_path(Path::new(name), v3), expected, "v3 {name}");
        }
    }

    #[test]
    fn ambiguous_h_headers_upgrade_to_cpp_only_on_an_obvious_cpp_marker() {
        for cpp in [
            "namespace demo { }",
            "template<class T> void f();",
            "template <class T> void f();",
            "extern \"C++\" void f();",
        ] {
            assert!(header_looks_cpp(cpp), "{cpp}");
            assert_eq!(
                language_for_source(LanguageKind::C, Path::new("a.h"), cpp),
                LanguageKind::Cpp
            );
        }
        assert!(!header_looks_cpp("int plain(void);"));
        assert_eq!(
            language_for_source(LanguageKind::C, Path::new("a.h"), "int plain(void);"),
            LanguageKind::C
        );
        // Only `.h` is ambiguous — a `.c` stays C even with a C++ marker.
        assert_eq!(
            language_for_source(LanguageKind::C, Path::new("a.c"), "namespace demo {}"),
            LanguageKind::C
        );
        // Non-C languages are never re-sniffed.
        assert_eq!(
            language_for_source(LanguageKind::Python, Path::new("a.h"), "namespace demo {}"),
            LanguageKind::Python
        );
    }

    #[test]
    fn generated_directory_skips_apply_only_to_the_extensions_their_tier_owns() {
        let generated = ["dist", "build", "out", ".next", ".nuxt", ".output", "coverage"];
        let v3_only = ["target", "vendor", "vendored", "third_party"];

        for dir in generated {
            let js = PathBuf::from(dir).join("bundle.js");
            assert!(!should_skip_generated_polyglot_file(&js, options(false, false)));
            assert!(should_skip_generated_polyglot_file(&js, options(true, false)));
            assert!(should_skip_generated_polyglot_file(&js, options(false, true)));
            let java = PathBuf::from(dir).join("Gen.java");
            assert!(!should_skip_generated_polyglot_file(&java, options(true, false)));
            assert!(should_skip_generated_polyglot_file(&java, options(false, true)));
            // TypeScript predates both tiers and is never skipped by directory.
            let ts = PathBuf::from(dir).join("gen.ts");
            assert!(!should_skip_generated_polyglot_file(&ts, options(true, true)));
        }
        for dir in v3_only {
            let js = PathBuf::from(dir).join("bundle.js");
            assert!(
                !should_skip_generated_polyglot_file(&js, options(true, true)),
                "{dir} is a V3-only vendor directory for JS"
            );
            let c = PathBuf::from(dir).join("gen.c");
            assert!(should_skip_generated_polyglot_file(&c, options(false, true)), "{dir}");
        }
        assert!(!should_skip_generated_polyglot_file(
            Path::new("src/app.js"),
            options(true, true)
        ));
    }

    #[test]
    fn v2_js_paths_and_source_limits_are_per_language() {
        for path in ["a.js", "a/b.jsx", "a.mjs", "a.cjs"] {
            assert!(is_v2_js_path(path), "{path}");
        }
        for path in ["a.ts", "a.tsx", "a", "a.json"] {
            assert!(!is_v2_js_path(path), "{path}");
        }
        assert_eq!(
            v3_source_limits(LanguageKind::Java),
            Some((POLYGLOT_JAVA_MAX_BYTES, POLYGLOT_JAVA_MAX_LINE_BYTES))
        );
        assert_eq!(
            v3_source_limits(LanguageKind::C),
            Some((POLYGLOT_C_MAX_BYTES, POLYGLOT_C_MAX_LINE_BYTES))
        );
        assert_eq!(
            v3_source_limits(LanguageKind::Cpp),
            Some((POLYGLOT_CPP_MAX_BYTES, POLYGLOT_CPP_MAX_LINE_BYTES))
        );
        assert_eq!(
            v3_source_limits(LanguageKind::CSharp),
            Some((POLYGLOT_CSHARP_MAX_BYTES, POLYGLOT_CSHARP_MAX_LINE_BYTES))
        );
        assert_eq!(
            v3_source_limits(LanguageKind::Ruby),
            Some((POLYGLOT_RUBY_MAX_BYTES, POLYGLOT_RUBY_MAX_LINE_BYTES))
        );
        assert_eq!(
            v3_source_limits(LanguageKind::Swift),
            Some((POLYGLOT_SWIFT_MAX_BYTES, POLYGLOT_SWIFT_MAX_LINE_BYTES))
        );
        assert_eq!(
            v3_source_limits(LanguageKind::Php),
            Some((POLYGLOT_PHP_MAX_BYTES, POLYGLOT_PHP_MAX_LINE_BYTES))
        );
        assert!(v3_source_limits(LanguageKind::Svelte).is_none());
        assert!(v3_source_limits(LanguageKind::TypeScript).is_none());
        assert!(v3_source_limits(LanguageKind::Go).is_none());
    }

    #[test]
    fn v2_js_pathology_skip_is_flag_and_extension_gated() {
        let long_line = "x".repeat(POLYGLOT_JS_MAX_LINE_BYTES + 1);
        assert!(!should_skip_pathological_v2_js(
            "a.js",
            &long_line,
            options(false, false)
        ));
        assert!(should_skip_pathological_v2_js("a.js", &long_line, options(true, false)));
        assert!(should_skip_pathological_v2_js("a.js", &long_line, options(false, true)));
        assert!(
            !should_skip_pathological_v2_js("a.ts", &long_line, options(true, true)),
            "the JS pathology gate is JS-only"
        );
        assert!(!should_skip_pathological_v2_js(
            "a.js",
            "const a = 1;\n",
            options(true, true)
        ));
    }

    #[test]
    fn ast_walk_guard_counts_only_the_calls_past_the_limit() {
        let mut guard = AstWalkGuard::default();
        assert!(guard.allow_depth(0));
        assert!(guard.allow_depth(POLYGLOT_AST_MAX_DEPTH));
        assert_eq!(guard.depth_limit_hits, 0);
        assert!(!guard.allow_depth(POLYGLOT_AST_MAX_DEPTH + 1));
        assert!(!guard.allow_depth(POLYGLOT_AST_MAX_DEPTH + 2));
        assert_eq!(guard.depth_limit_hits, 2);
    }

    // ---------------------------------------------------------------------
    // Degenerate sources
    // ---------------------------------------------------------------------

    #[test]
    #[serial_test::serial]
    fn empty_comment_only_and_broken_sources_scan_without_symbols_or_errors() {
        let _v2 = EnvVarGuard::set(POLYGLOT_V2_ENV, "1");
        let _v3 = EnvVarGuard::set(POLYGLOT_V3_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        for (name, source) in [
            ("empty.ts", ""),
            ("comments.ts", "// nothing here\n// really nothing\n"),
            ("broken.ts", "export function ( { { {\n"),
            ("empty.py", ""),
            ("broken.py", "def (:\n  ???\n"),
            ("empty.go", ""),
            ("broken.go", "func ( { }{\n"),
            ("Broken.java", "class { public void ( }\n"),
            ("broken.rb", "class ; def ; end\n"),
            ("broken.php", "<?php class { function ( }\n"),
            ("notes.txt", "not a source file at all\n"),
            ("noextension", "still not a source file\n"),
        ] {
            std::fs::write(tmp.path().join(name), source).expect("source");
        }

        let scan = run_repo_scan_at(tmp.path()).expect("scan");
        for unscanned in ["notes.txt", "noextension"] {
            assert!(
                !scan.files.iter().any(|f| f.rel_path == unscanned),
                "{unscanned} is not a supported extension"
            );
        }
        for scanned in ["empty.ts", "comments.ts", "broken.ts", "broken.py", "Broken.java"] {
            assert!(
                scan.files.iter().any(|f| f.rel_path == scanned),
                "{scanned} should still be listed"
            );
        }
        let empty = scan.files.iter().find(|f| f.rel_path == "empty.ts").expect("empty.ts");
        assert_eq!(empty.loc, 0);
        assert_eq!(empty.symbol_count, 0);
        assert!(
            scan.diagnostics.v3_skipped_files.is_empty(),
            "a broken source is not a skipped source"
        );
    }

    /// DEFECT PIN — a source whose parse produces no usable nodes is reported
    /// exactly like a source that genuinely declares nothing: present in
    /// `files`, `symbol_count` 0, no diagnostic. `v3_skipped_files` records only
    /// files rejected *before* parsing (size/line/depth caps), never a parse that
    /// yielded nothing.
    #[test]
    #[serial_test::serial]
    fn a_broken_source_is_indistinguishable_from_an_empty_one_in_the_scan() {
        let _v3 = EnvVarGuard::set(POLYGLOT_V3_ENV, "1");
        let broken = tempfile::tempdir().expect("tempdir");
        std::fs::write(broken.path().join("a.ts"), "export function ( { {\n").expect("broken");
        let empty = tempfile::tempdir().expect("tempdir");
        std::fs::write(empty.path().join("a.ts"), "// a comment\n").expect("empty");

        let broken_file = run_repo_scan_at(broken.path())
            .expect("scan")
            .files
            .into_iter()
            .find(|f| f.rel_path == "a.ts")
            .expect("broken a.ts");
        let empty_file = run_repo_scan_at(empty.path())
            .expect("scan")
            .files
            .into_iter()
            .find(|f| f.rel_path == "a.ts")
            .expect("empty a.ts");
        assert_eq!(broken_file.symbol_count, empty_file.symbol_count);
        assert_eq!(broken_file.loc, empty_file.loc);
    }

    #[test]
    #[serial_test::serial]
    fn svelte_files_are_listed_but_never_extracted() {
        let _v3 = EnvVarGuard::set(POLYGLOT_V3_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("Page.svelte"),
            "<script>export function handler() {}</script>\n<h1>hi</h1>\n",
        )
        .expect("svelte");
        let scan = run_repo_scan_at(tmp.path()).expect("scan");
        assert!(scan.files.iter().any(|f| f.rel_path == "Page.svelte"));
        assert!(
            symbol_set(&scan, "Page.svelte").is_empty(),
            "Svelte extraction is deliberately a no-op"
        );
    }

    // ---------------------------------------------------------------------
    // Package naming and module paths
    // ---------------------------------------------------------------------

    #[test]
    fn package_name_prefers_package_json_then_pyproject_then_setup_cfg_then_the_directory() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path().join("fallback-dir");
        std::fs::create_dir_all(&dir).expect("dir");
        assert_eq!(discover_package_name(&dir), "fallback-dir");

        std::fs::write(dir.join("setup.cfg"), "[metadata]\nname = from_setup_cfg\n").expect("setup.cfg");
        assert_eq!(discover_package_name(&dir), "from_setup_cfg");

        std::fs::write(dir.join("pyproject.toml"), "[project]\nname = \"from_pyproject\"\n").expect("pyproject");
        assert_eq!(discover_package_name(&dir), "from_pyproject");

        std::fs::write(dir.join("package.json"), r#"{"name":"from-package-json"}"#).expect("package.json");
        assert_eq!(discover_package_name(&dir), "from-package-json");
    }

    #[test]
    fn package_name_readers_ignore_unreadable_malformed_and_wrong_section_files() {
        let tmp = tempfile::tempdir().expect("tempdir");
        assert!(package_json_name(&tmp.path().join("absent.json")).is_none());
        assert!(pyproject_name(&tmp.path().join("absent.toml")).is_none());
        assert!(setup_cfg_name(&tmp.path().join("absent.cfg")).is_none());

        std::fs::write(tmp.path().join("bad.json"), "{not json").expect("bad json");
        assert!(package_json_name(&tmp.path().join("bad.json")).is_none());
        std::fs::write(tmp.path().join("nameless.json"), "{}").expect("nameless");
        assert!(package_json_name(&tmp.path().join("nameless.json")).is_none());

        std::fs::write(
            tmp.path().join("other-section.toml"),
            "[tool.poetry]\nname = \"ignored\"\n",
        )
        .expect("pyproject");
        assert!(pyproject_name(&tmp.path().join("other-section.toml")).is_none());

        std::fs::write(tmp.path().join("other.cfg"), "[options]\nname = ignored\n").expect("cfg");
        assert!(setup_cfg_name(&tmp.path().join("other.cfg")).is_none());
        assert_eq!(quoted_value("name = 'single'").as_deref(), Some("single"));
        assert!(quoted_value("no equals sign").is_none());
    }

    #[test]
    fn module_path_strips_language_suffixes_and_normalizes_separators() {
        assert_eq!(module_path("pkg", "src/app.ts"), "pkg::src::app");
        assert_eq!(module_path("my-pkg", "src/app.tsx"), "my_pkg::src::app");
        assert_eq!(module_path("pkg", "src/mod.py"), "pkg::src::mod");
        assert_eq!(module_path("pkg", "a/b.vue"), "pkg::a::b");
        assert_eq!(module_path("pkg", "a/b.svelte"), "pkg::a::b");
        assert_eq!(module_path("pkg", "a/b.go"), "pkg::a::b");
        assert_eq!(module_path("pkg", "a/b.rs"), "pkg::a::b");
        assert_eq!(module_path("pkg", "Svc.java"), "pkg::Svc");
        assert_eq!(module_path("pkg", "Svc.swift"), "pkg::Svc");
        assert_eq!(module_path("pkg", "svc.php"), "pkg::svc");
        assert_eq!(module_path("pkg", "svc.cpp"), "pkg::svc");
        assert_eq!(module_path("pkg", "svc.h"), "pkg::svc");
        assert_eq!(module_path("pkg", "kebab-name.ts"), "pkg::kebab::name");
        assert_eq!(
            module_path("pkg", "web.c.ts"),
            "pkg::web.c",
            "a V3 suffix must not eat a legacy file's `.c` component"
        );
        assert_eq!(module_path("pkg", "README"), "pkg::README");
    }

    #[test]
    fn rel_string_keeps_paths_outside_the_root_absolute() {
        assert_eq!(rel_string(Path::new("/repo"), Path::new("/repo/a/b.ts")), "a/b.ts");
        assert_eq!(rel_string(Path::new("/repo"), Path::new("/other/b.ts")), "/other/b.ts");
    }

    #[test]
    fn package_infos_falls_back_to_the_default_name_for_an_empty_scan() {
        let scan = WorkspaceScan::default();
        let packages = package_infos(Path::new("/repo"), &scan, "fallback");
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "fallback");
        assert_eq!(packages[0].file_count, 0);
        assert_eq!(packages[0].total_loc, 0);
        assert_eq!(packages[0].rel_path, "/repo");
        assert!(packages[0].internal_deps.is_empty());
    }

    #[test]
    #[serial_test::serial]
    fn rust_workspace_detection_needs_both_a_manifest_and_a_rust_file() {
        let _v2 = EnvVarGuard::unset(POLYGLOT_V2_ENV);
        let _v3 = EnvVarGuard::unset(POLYGLOT_V3_ENV);
        let tmp = tempfile::tempdir().expect("tempdir");
        assert!(!has_rust_workspace(tmp.path()));
        std::fs::write(tmp.path().join("Cargo.toml"), "[workspace]\n").expect("manifest");
        assert!(!has_rust_workspace(tmp.path()), "a manifest alone is not a workspace");
        std::fs::create_dir_all(tmp.path().join("src")).expect("src");
        std::fs::write(tmp.path().join("src/main.rs"), "fn main() {}\n").expect("main.rs");
        assert!(has_rust_workspace(tmp.path()));
        assert!(should_use_rust_workspace_scan(tmp.path()));

        // A polyglot file flips the scan into hybrid mode.
        std::fs::write(tmp.path().join("src/app.ts"), "export const x = 1;\n").expect("ts");
        assert!(!should_use_rust_workspace_scan(tmp.path()));
    }

    #[test]
    fn polyglot_non_rust_detection_widens_with_each_flag_tier() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("a.go"), "package main\n").expect("go");
        assert!(!has_polyglot_non_rust_files(tmp.path(), options(false, false)));
        assert!(has_polyglot_non_rust_files(tmp.path(), options(true, false)));

        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("A.java"), "class A {}\n").expect("java");
        assert!(!has_polyglot_non_rust_files(tmp.path(), options(true, false)));
        assert!(has_polyglot_non_rust_files(tmp.path(), options(false, true)));

        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("a.ts"), "export const x = 1;\n").expect("ts");
        assert!(has_polyglot_non_rust_files(tmp.path(), options(false, false)));
        assert!(has_supported_file(tmp.path(), &[Some("ts")]));
        assert!(!has_supported_file(tmp.path(), &[Some("rs")]));
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_flags_read_the_shared_env_flag_helper() {
        {
            let _v2 = EnvVarGuard::set(POLYGLOT_V2_ENV, "1");
            let _v3 = EnvVarGuard::set(POLYGLOT_V3_ENV, "off");
            assert!(polyglot_v2_enabled_from_env());
            assert!(!polyglot_v3_enabled());
        }
        let _v2 = EnvVarGuard::unset(POLYGLOT_V2_ENV);
        let _v3 = EnvVarGuard::unset(POLYGLOT_V3_ENV);
        assert!(!polyglot_v2_enabled_from_env());
        assert!(!polyglot_v3_enabled());
    }

    // ---------------------------------------------------------------------
    // Shared literal / comment scanning helpers
    // ---------------------------------------------------------------------

    #[test]
    fn literal_text_value_honours_string_prefixes_and_backtick_gating() {
        assert_eq!(literal_text_value("\"plain\"", false).as_deref(), Some("plain"));
        assert_eq!(literal_text_value("  'single'", false).as_deref(), Some("single"));
        assert_eq!(literal_text_value("r\"raw\"", false).as_deref(), Some("raw"));
        assert_eq!(literal_text_value("b'bytes'", false).as_deref(), Some("bytes"));
        assert_eq!(literal_text_value("U\"unicode\"", false).as_deref(), Some("unicode"));
        assert!(
            literal_text_value("f\"{interpolated}\"", false).is_none(),
            "f-strings are not static literals"
        );
        assert!(
            literal_text_value("name(\"x\")", false).is_none(),
            "a non-prefix character before the quote disqualifies the literal"
        );
        assert!(literal_text_value("`tpl`", false).is_none());
        assert_eq!(literal_text_value("`tpl`", true).as_deref(), Some("tpl"));
        assert!(literal_text_value("no quotes", false).is_none());
        assert!(literal_text_value("\"unterminated", false).is_none());
        assert_eq!(
            first_literal_from_arg_text("   \"padded\"", false).as_deref(),
            Some("padded")
        );
    }

    #[test]
    fn find_closing_quote_respects_escapes_except_inside_backticks() {
        assert_eq!(find_closing_quote("abc\"rest", b'"'), Some(3));
        assert_eq!(find_closing_quote("a\\\"b\"rest", b'"'), Some(4));
        assert_eq!(
            find_closing_quote("a\\`b`", b'`'),
            Some(2),
            "a backslash does not escape inside backticks"
        );
        assert!(find_closing_quote("no close", b'"').is_none());
    }

    #[test]
    fn quoted_and_ruby_literal_scanners_stop_at_an_unterminated_quote() {
        assert_eq!(
            quoted_literals("a \"one\" b 'two' c"),
            vec!["one".to_string(), "two".to_string()]
        );
        assert!(quoted_literals("\"unterminated").is_empty());
        assert!(quoted_literals("no literals").is_empty());
        assert_eq!(
            ruby_static_literals("only: [:index, :show], path: \"p\""),
            vec!["index".to_string(), "show".to_string(), "p".to_string()],
            "`path:` is an option name, not a symbol literal"
        );
        assert!(
            ruby_static_literals("Demo::Service").is_empty(),
            "`::` is not a symbol marker"
        );
        assert!(ruby_static_literals("\"unterminated").is_empty());
    }

    #[test]
    fn line_comment_stripping_ignores_markers_inside_quotes() {
        assert_eq!(strip_hash_comment("gem \"a\" # trailing"), "gem \"a\" ");
        assert_eq!(strip_hash_comment("gem \"a#b\""), "gem \"a#b\"");
        assert_eq!(strip_hash_comment("no comment"), "no comment");
        assert_eq!(strip_double_slash_comment("code // trailing"), "code ");
        assert_eq!(
            strip_double_slash_comment("url(\"https://example.invalid\")"),
            "url(\"https://example.invalid\")"
        );
        assert_eq!(strip_double_slash_comment("a / b"), "a / b");
        assert_eq!(strip_php_line_comment("$x = 1; # hash"), "$x = 1; ");
        assert_eq!(strip_php_line_comment("$x = 1; // slash"), "$x = 1; ");
        assert_eq!(strip_line_comment_outside_quotes("a 'b\\'c' # d", '#'), "a 'b\\'c' ");
    }

    #[test]
    fn brace_delta_ignores_braces_inside_strings_and_saturates_at_zero() {
        assert_eq!(source_brace_delta("{ {"), 2);
        assert_eq!(source_brace_delta("} }"), -2);
        assert_eq!(source_brace_delta("{ }"), 0);
        assert_eq!(source_brace_delta("\"{ { {\""), 0);
        assert_eq!(source_brace_delta("'{' + x + '}'"), 0);
        assert_eq!(source_brace_delta("\"a\" {"), 1);
        assert_eq!(apply_brace_delta(3, 2), 5);
        assert_eq!(apply_brace_delta(3, -2), 1);
        assert_eq!(apply_brace_delta(1, -5), 0);
    }

    #[test]
    fn join_route_paths_normalizes_every_empty_and_slash_combination() {
        assert_eq!(join_route_paths("", ""), "");
        assert_eq!(join_route_paths("", "users"), "/users");
        assert_eq!(join_route_paths("/api/", "/users/"), "/api/users");
        assert_eq!(join_route_paths("api", ""), "/api");
        assert_eq!(join_route_paths("/", "/"), "");
        assert_eq!(join_spring_paths("", ""), "/", "spring never emits an empty path");
        assert_eq!(join_spring_paths("/api", "users"), "/api/users");
    }

    #[test]
    fn vue_script_blocks_span_multiple_blocks_and_stop_at_malformed_tags() {
        let blocks = vue_script_blocks(
            "<template>x</template>\n<script>const a = 1;</script>\n<script setup>const b = 2;</script>\n",
        );
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].text, "const a = 1;");
        assert_eq!(blocks[0].start_line_offset, 1);
        assert_eq!(blocks[1].text, "const b = 2;");
        assert_eq!(blocks[1].start_line_offset, 2);
        assert!(vue_script_blocks("<template>only</template>").is_empty());
        assert!(
            vue_script_blocks("<script>never closed").is_empty(),
            "an unclosed script block yields nothing"
        );
        assert!(vue_script_blocks("<script").is_empty());
    }

    #[test]
    fn line_of_reports_a_one_based_line_or_zero_when_absent() {
        assert_eq!(line_of("a\nneedle\nb\n", "needle"), 2);
        assert_eq!(line_of("a\nb\n", "needle"), 0);
    }

    #[test]
    fn rust_use_paths_flattens_every_tree_shape() {
        let mut guard = AstWalkGuard::default();
        let parse = |src: &str, guard: &mut AstWalkGuard| {
            let item: syn::ItemUse = syn::parse_str(src).expect("use item");
            rust_use_paths(&item.tree, guard)
        };
        assert_eq!(parse("use a::b::c;", &mut guard), vec!["a::b::c".to_string()]);
        assert_eq!(parse("use a::b as c;", &mut guard), vec!["a::b".to_string()]);
        assert_eq!(parse("use a::*;", &mut guard), vec!["a::*".to_string()]);
        assert_eq!(
            parse("use a::{b, c::d};", &mut guard),
            vec!["a::b".to_string(), "a::c::d".to_string()]
        );
        assert_eq!(guard.depth_limit_hits, 0);
    }

    #[test]
    fn polyglot_is_pub_matches_public_and_restricted_visibility() {
        assert!(is_pub(&syn::parse_str::<syn::Visibility>("pub").expect("pub")));
        assert!(is_pub(
            &syn::parse_str::<syn::Visibility>("pub(crate)").expect("pub(crate)")
        ));
        assert!(!is_pub(&syn::Visibility::Inherited));
    }

    #[test]
    fn python_import_module_reads_from_and_import_forms() {
        assert_eq!(python_import_module("from a.b import c").as_deref(), Some("a.b"));
        assert_eq!(python_import_module("  import a.b  ").as_deref(), Some("a.b"));
        assert_eq!(python_import_module("import a, b").as_deref(), Some("a"));
        assert!(python_import_module("x = 1").is_none());
        assert!(python_import_module("import ").is_none());
    }

    #[test]
    fn qualify_parts_and_c_family_name_normalizers() {
        assert_eq!(
            qualify_parts(&["Ns".to_string()], &["Cls".to_string()], "method", "."),
            "Ns.Cls.method"
        );
        assert_eq!(qualify_parts(&["Ns".to_string()], &[], "fn", "\\"), "Ns\\fn");
        assert_eq!(qualify_parts(&[], &[], "bare", "::"), "bare");
        assert_eq!(
            qualify_parts(&["Ns".to_string()], &["Cls".to_string()], "", "::"),
            "Ns::Cls"
        );
        assert_eq!(normalize_c_family_name("  a b\tc "), "abc");
    }

    #[test]
    fn qualify_cpp_callable_avoids_double_qualification() {
        let state = CFamilyWalkState {
            namespaces: vec!["ns".to_string()],
            classes: vec!["Cls".to_string()],
            ..CFamilyWalkState::default()
        };
        assert_eq!(qualify_cpp_callable("method", &state), "ns::Cls::method");
        assert_eq!(
            qualify_cpp_callable("ns::Cls::method", &state),
            "ns::Cls::method",
            "an already-qualified name is not re-prefixed"
        );
        assert_eq!(qualify_cpp_callable("::ns::Cls::m", &state), "ns::Cls::m");
        assert_eq!(qualify_cpp_callable("Other::m", &state), "ns::Other::m");
        let bare = CFamilyWalkState::default();
        assert_eq!(qualify_cpp_callable("Other::m", &bare), "Other::m");
        assert_eq!(qualify_cpp_callable("plain", &bare), "plain");
    }

    #[test]
    fn source_word_scanning_skips_declaration_keywords() {
        assert_eq!(first_source_identifier("let name = 1").as_deref(), Some("name"));
        assert_eq!(
            first_source_identifier("public static Thing x").as_deref(),
            Some("Thing")
        );
        assert_eq!(first_source_identifier("class Foo").as_deref(), Some("Foo"));
        assert!(first_source_identifier("   ").is_none());
        assert_eq!(source_words("a.b-c_d").collect::<Vec<_>>(), vec!["a", "b", "c_d"]);
    }

    // ---------------------------------------------------------------------
    // Route helper matrices
    // ---------------------------------------------------------------------

    #[test]
    fn express_methods_and_receiver_allowlists() {
        for (name, expected) in [
            ("get", Some("GET")),
            ("post", Some("POST")),
            ("put", Some("PUT")),
            ("delete", Some("DELETE")),
            ("patch", Some("PATCH")),
            ("head", Some("HEAD")),
            ("options", Some("OPTIONS")),
            ("all", Some("ANY")),
            ("listen", None),
        ] {
            assert_eq!(express_method(name).as_deref(), expected, "{name}");
        }
        for allowed in ["app", "router", "server", "srv", "fastify", "express", "r", "apiRouter"] {
            assert!(ts_express_receiver_allowed(allowed), "{allowed}");
        }
        assert!(!ts_express_receiver_allowed("axios"));
        for allowed in [
            "r", "router", "mux", "engine", "g", "e", "app", "srv", "group", "apiMux", "v1Group", "myEngine",
        ] {
            assert!(go_route_receiver_allowed(allowed), "{allowed}");
        }
        assert!(!go_route_receiver_allowed("client"));
    }

    #[test]
    fn nest_method_decorators_map_verbs_and_optional_paths() {
        assert_eq!(
            parse_nest_method_decorator("@Get()"),
            Some(("GET".to_string(), String::new()))
        );
        assert_eq!(
            parse_nest_method_decorator("@Post('items')"),
            Some(("POST".to_string(), "items".to_string()))
        );
        for (raw, method) in [
            ("@Put()", "PUT"),
            ("@Delete()", "DELETE"),
            ("@Patch()", "PATCH"),
            ("@Head()", "HEAD"),
            ("@Options()", "OPTIONS"),
            ("@All()", "ANY"),
        ] {
            assert_eq!(
                parse_nest_method_decorator(raw).map(|(m, _)| m),
                Some(method.to_string())
            );
        }
        assert!(parse_nest_method_decorator("@Injectable()").is_none());
        assert!(parse_nest_method_decorator("@Get").is_some());
    }

    #[test]
    fn aspnet_route_paths_substitute_tokens_and_honour_absolute_forms() {
        assert_eq!(aspnet_route_path("api/[controller]", "", "Users", "List"), "/api/Users");
        assert_eq!(
            aspnet_route_path("api/[Controller]", "[action]", "Users", "List"),
            "/api/Users/List"
        );
        assert_eq!(
            aspnet_route_path("api/[controller]", "/absolute/[Action]", "Users", "List"),
            "/absolute/List"
        );
        assert_eq!(
            aspnet_route_path("api/[controller]", "~/root/[controller]", "Users", "List"),
            "/root/Users"
        );
        assert_eq!(
            aspnet_route_path("api/[area]", "", "Users", "List"),
            "/api/[area]",
            "[area] is deliberately left unresolved"
        );
    }

    #[test]
    fn spring_annotation_names_args_paths_and_methods() {
        assert_eq!(
            spring_annotation_name("@org.springframework.GetMapping(\"/x\")"),
            "GetMapping"
        );
        assert_eq!(spring_annotation_name("  @RestController  "), "RestController");
        assert_eq!(spring_annotation_args("@GetMapping(\"/x\", y)"), "\"/x\", y");
        assert_eq!(spring_annotation_args("@RestController"), "");

        assert!(matches!(
            spring_annotation_paths("@GetMapping"),
            SpringAnnotationPaths::Static(paths) if paths == vec![String::new()]
        ));
        assert!(matches!(
            spring_annotation_paths("@GetMapping(\"/a\")"),
            SpringAnnotationPaths::Static(paths) if paths == vec!["/a".to_string()]
        ));
        assert!(matches!(
            spring_annotation_paths("@RequestMapping(value = {\"/a\", \"/b\"})"),
            SpringAnnotationPaths::Static(paths) if paths == vec!["/a".to_string(), "/b".to_string()]
        ));
        assert!(matches!(
            spring_annotation_paths("@GetMapping(path = PATH_CONSTANT)"),
            SpringAnnotationPaths::Dynamic
        ));
        assert!(matches!(
            spring_annotation_paths("@RequestMapping(method = RequestMethod.GET)"),
            SpringAnnotationPaths::Static(paths) if paths == vec![String::new()]
        ));

        assert_eq!(
            spring_request_methods("@RequestMapping(\"/a\")"),
            vec!["ANY".to_string()]
        );
        assert_eq!(
            spring_request_methods("@RequestMapping(method = RequestMethod.GET)"),
            vec!["GET".to_string()]
        );
        assert_eq!(
            spring_request_methods("@RequestMapping(method = {RequestMethod.PUT, RequestMethod.PATCH})"),
            vec!["PUT".to_string(), "PATCH".to_string()]
        );
        assert_eq!(
            spring_request_methods("@RequestMapping(method = someExpression)"),
            vec!["ANY".to_string()]
        );
    }

    #[test]
    fn top_level_argument_splitting_respects_nesting_quotes_and_escapes() {
        assert_eq!(split_top_level_args(""), vec![""]);
        assert_eq!(split_top_level_args("a, b"), vec!["a", "b"]);
        assert_eq!(split_top_level_args("a, {b, c}, d"), vec!["a", "{b, c}", "d"]);
        assert_eq!(split_top_level_args("\"a, b\", c"), vec!["\"a, b\"", "c"]);
        assert_eq!(split_top_level_args("f(x, y), z"), vec!["f(x, y)", "z"]);
        assert_eq!(split_top_level_args("[a, b], c"), vec!["[a, b]", "c"]);
        assert_eq!(split_top_level_args(r#""a\", b", c"#), vec![r#""a\", b""#, "c"]);
        assert_eq!(
            all_literal_values("{\"/a\", \"/b\"}"),
            vec!["/a".to_string(), "/b".to_string()]
        );
        assert!(all_literal_values("CONSTANT").is_empty());
    }

    #[test]
    fn rails_route_path_gate_and_line_helpers() {
        assert!(is_rails_routes_path("config/routes.rb"));
        assert!(is_rails_routes_path("apps/web/config/routes.rb"));
        assert!(!is_rails_routes_path("config/routes_draw.rb"));
        assert!(!is_rails_routes_path("app/models/user.rb"));

        assert_eq!(rails_route_method("get \"/a\""), Some(("GET", " \"/a\"")));
        assert_eq!(rails_route_method("post(\"/a\")"), Some(("POST", "(\"/a\")")));
        assert_eq!(rails_route_method("put \"/a\"").map(|(m, _)| m), Some("PUT"));
        assert_eq!(rails_route_method("patch \"/a\"").map(|(m, _)| m), Some("PATCH"));
        assert_eq!(rails_route_method("delete \"/a\"").map(|(m, _)| m), Some("DELETE"));
        assert!(rails_route_method("getter \"/a\"").is_none());
        assert!(rails_route_method("resources :users").is_none());

        assert_eq!(rails_scope_path("scope \"/admin\"").as_deref(), Some("/admin"));
        assert_eq!(rails_scope_path("scope(\"/admin\")").as_deref(), Some("/admin"));
        assert_eq!(
            rails_scope_path("scope module: :admin, path: \"/a\"").as_deref(),
            Some("/a")
        );
        assert!(rails_scope_path("namespace :admin").is_none());

        assert_eq!(
            rails_option_value("to: \"users#index\"", "to").as_deref(),
            Some("users#index")
        );
        assert_eq!(
            rails_option_value("to: :symbolic, x: 1", "to").as_deref(),
            Some("symbolic")
        );
        assert!(rails_option_value("to: SOME_CONST", "to").is_none());
        assert!(rails_option_value("no option here", "to").is_none());

        assert_eq!(
            rails_symbol_argument("namespace :admin do", "namespace").as_deref(),
            Some("admin")
        );
        assert_eq!(
            rails_symbol_argument("namespace \"admin\" do", "namespace").as_deref(),
            Some("admin")
        );
        assert!(rails_symbol_argument("namespaced :admin", "namespace").is_none());
        assert!(rails_symbol_argument("namespace admin", "namespace").is_none());
    }

    #[test]
    fn rails_resource_names_and_action_filters() {
        assert_eq!(
            rails_resource_names("resources :users, :posts"),
            vec!["users".to_string(), "posts".to_string()]
        );
        assert_eq!(rails_resource_names("resources(:users)"), vec!["users".to_string()]);
        assert_eq!(
            rails_resource_names("resources :users, only: [:index]"),
            vec!["users".to_string()],
            "option values are not resource names"
        );
        assert!(rails_resource_names("resourceful :users").is_empty());
        assert!(rails_resource_names("resource :user").is_empty());

        let all: BTreeSet<String> = ["index", "show", "new", "create", "edit", "update", "destroy"]
            .into_iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            rails_resource_actions("resources :users")
                .into_iter()
                .collect::<BTreeSet<_>>(),
            all
        );
        assert_eq!(
            rails_resource_actions("resources :users, only: [:index, :show]")
                .into_iter()
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["index".to_string(), "show".to_string()])
        );
        assert!(!rails_resource_actions("resources :users, except: [:destroy]").contains("destroy"));
        assert!(
            rails_resource_actions("resources :users, only: [:bogus]").is_empty(),
            "unknown actions are filtered out rather than invented"
        );
        assert_eq!(
            rails_option_symbols("only: :index", "only"),
            Some(HashSet::from(["index".to_string()]))
        );
        assert!(rails_option_symbols("no such option", "only").is_none());
    }

    #[test]
    fn laravel_route_gate_group_prefixes_and_handlers() {
        assert!(is_laravel_routes_path("routes/web.php"));
        assert!(is_laravel_routes_path("apps/api/routes/api.php"));
        assert!(!is_laravel_routes_path("routes/web.rb"));
        assert!(!is_laravel_routes_path("app/Http/Controllers/UserController.php"));

        assert_eq!(laravel_route_method("Route::get('/a', X)").map(|(m, _)| m), Some("GET"));
        assert_eq!(
            laravel_route_method("Route::post('/a', X)").map(|(m, _)| m),
            Some("POST")
        );
        assert_eq!(laravel_route_method("Route::put('/a', X)").map(|(m, _)| m), Some("PUT"));
        assert_eq!(
            laravel_route_method("Route::patch('/a', X)").map(|(m, _)| m),
            Some("PATCH")
        );
        assert_eq!(
            laravel_route_method("Route::delete('/a', X)").map(|(m, _)| m),
            Some("DELETE")
        );
        assert!(laravel_route_method("Route::getSomething('/a')").is_none());
        assert!(laravel_route_method("Router::get('/a')").is_none());

        assert_eq!(
            laravel_group_prefix("Route::group(['prefix' => 'admin'], function () {").as_deref(),
            Some("admin")
        );
        assert_eq!(
            laravel_group_prefix("Route::group([], function () {").as_deref(),
            Some(""),
            "a group without a prefix is still a group frame"
        );
        assert_eq!(
            laravel_group_prefix("Route::prefix('api')->group(function () {").as_deref(),
            Some("api")
        );
        assert!(laravel_group_prefix("Route::get('/a', X);").is_none());
        assert_eq!(
            laravel_fluent_prefix("Route::prefix('v1')->group(").as_deref(),
            Some("v1")
        );
        assert!(laravel_fluent_prefix("Route::middleware('auth')->group(").is_none());

        assert_eq!(laravel_handler("function () {}").as_deref(), Some("closure"));
        assert_eq!(laravel_handler("static function () {}").as_deref(), Some("closure"));
        assert_eq!(laravel_handler("fn () => 1").as_deref(), Some("closure"));
        assert_eq!(
            laravel_handler("[UserController::class, 'index']").as_deref(),
            Some("UserController::index")
        );
        assert!(laravel_handler("'UserController@index'").is_none());
        assert!(laravel_array_handler("[UserController::class]").is_none());
        assert!(laravel_array_handler("no array").is_none());
    }

    #[test]
    fn laravel_argument_splitting_and_php_class_literals() {
        assert_eq!(
            laravel_call_arguments("Route::get('/a', [C::class, 'm'])"),
            vec!["'/a'".to_string(), "[C::class, 'm']".to_string()]
        );
        assert_eq!(
            laravel_call_arguments("f('a, b', c)"),
            vec!["'a, b'".to_string(), "c".to_string()]
        );
        assert_eq!(
            laravel_call_arguments("f(g(1, 2), 3)"),
            vec!["g(1, 2)".to_string(), "3".to_string()]
        );
        assert!(laravel_call_arguments("no parens").is_empty());
        assert_eq!(
            laravel_call_arguments("f(unterminated, args"),
            vec!["unterminated".to_string(), "args".to_string()]
        );

        assert_eq!(
            php_class_literal("App\\Http\\C::class").as_deref(),
            Some("App\\Http\\C")
        );
        assert_eq!(php_class_literal("[C::class, 'm']").as_deref(), Some("C"));
        assert!(php_class_literal("::class").is_none());
        assert!(php_class_literal("no class literal").is_none());

        assert_eq!(
            laravel_resource_arguments("Route::resource('users', UserController::class)"),
            Some(("users".to_string(), "UserController".to_string()))
        );
        assert!(laravel_resource_arguments("Route::resource($dynamic, C::class)").is_none());
        assert!(laravel_resource_arguments("Route::resource('users', $controller)").is_none());
    }

    #[test]
    fn go_receiver_and_export_helpers() {
        assert_eq!(go_receiver_type_name("(s *Server)"), "Server");
        assert_eq!(go_receiver_type_name("(s Server)"), "Server");
        assert_eq!(go_receiver_type_name("Server"), "Server");
        assert_eq!(go_receiver_type_name("  ( s   *pkg.Server )  "), "pkg.Server");
        assert!(go_is_pub("Exported"));
        assert!(!go_is_pub("unexported"));
        assert!(!go_is_pub(""));
        assert!(is_go_path("a/b.go"));
        assert!(is_go_path("a/b.GO"));
        assert!(!is_go_path("a/b.rs"));
        assert_eq!(path_dir("a/b/c.go"), "a/b");
        assert_eq!(path_dir("c.go"), "");
        assert_eq!(path_dir("a\\b\\c.go"), "a\\b");
    }

    // ---------------------------------------------------------------------
    // File-based route path derivation
    // ---------------------------------------------------------------------

    #[test]
    fn nextjs_file_routes_cover_pages_app_and_the_reserved_names() {
        assert_eq!(nextjs_file_route("pages/index.tsx"), Some(("/".to_string(), false)));
        assert_eq!(
            nextjs_file_route("src/pages/blog/[slug].tsx"),
            Some(("/blog/[slug]".to_string(), false))
        );
        assert_eq!(
            nextjs_file_route("pages/api/users.ts"),
            Some(("/api/users".to_string(), true))
        );
        for reserved in [
            "pages/_app.tsx",
            "pages/_document.tsx",
            "pages/_error.tsx",
            "pages/api/_helper.ts",
        ] {
            assert!(nextjs_file_route(reserved).is_none(), "{reserved}");
        }
        assert_eq!(
            nextjs_file_route("app/dashboard/page.tsx"),
            Some(("/dashboard".to_string(), false))
        );
        assert_eq!(
            nextjs_file_route("app/api/items/route.ts"),
            Some(("/api/items".to_string(), true))
        );
        assert_eq!(nextjs_file_route("app/page.tsx"), Some(("/".to_string(), false)));
        assert!(nextjs_file_route("app/dashboard/layout.tsx").is_none());
        assert!(
            nextjs_file_route("app/api/items/route.tsx").is_none(),
            "route.tsx is not a handler"
        );
        assert!(nextjs_file_route("components/Button.tsx").is_none());
        assert!(nextjs_file_route("pages/styles.css").is_none());
        assert!(nextjs_file_route("").is_none());
    }

    #[test]
    fn next_app_router_segment_normalization_drops_groups_slots_and_interceptors() {
        assert_eq!(
            normalize_next_app_segments(&["(marketing)", "about"]),
            vec!["about".to_string()]
        );
        assert_eq!(
            normalize_next_app_segments(&["@modal", "photo"]),
            vec!["photo".to_string()]
        );
        assert_eq!(normalize_next_app_segments(&["(.)photo"]), vec!["photo".to_string()]);
        assert_eq!(normalize_next_app_segments(&["(..)photo"]), vec!["photo".to_string()]);
        assert_eq!(normalize_next_app_segments(&["(...)photo"]), vec!["photo".to_string()]);
        assert_eq!(
            normalize_next_app_segments(&["(..)(..)photo"]),
            vec!["photo".to_string()]
        );
        assert!(normalize_next_app_segments(&["(.)"]).is_empty());
        assert_eq!(normalize_next_app_segments(&["[id]"]), vec!["[id]".to_string()]);
    }

    #[test]
    fn nuxt_and_sveltekit_file_routes_are_derived_from_their_conventions() {
        assert_eq!(nuxt_file_route("pages/index.vue").as_deref(), Some("/"));
        assert_eq!(
            nuxt_file_route("src/pages/blog/[id].vue").as_deref(),
            Some("/blog/[id]")
        );
        assert!(nuxt_file_route("pages/index.ts").is_none());
        assert!(nuxt_file_route("components/Card.vue").is_none());

        assert_eq!(
            sveltekit_file_route("src/routes/+page.svelte"),
            Some(("/".to_string(), false))
        );
        assert_eq!(
            sveltekit_file_route("src/routes/(app)/dash/+page.svelte"),
            Some(("/dash".to_string(), false))
        );
        assert_eq!(
            sveltekit_file_route("src/routes/api/+server.ts"),
            Some(("/api".to_string(), true))
        );
        assert_eq!(
            sveltekit_file_route("src/routes/api/+server.js").map(|(_, server)| server),
            Some(true)
        );
        assert!(sveltekit_file_route("src/routes/+layout.svelte").is_none());
        assert!(sveltekit_file_route("routes/+page.svelte").is_none());
    }

    #[test]
    fn router_root_index_and_path_segment_helpers() {
        assert_eq!(router_root_index(&["pages", "a"], "pages"), Some(0));
        assert_eq!(router_root_index(&["src", "pages", "a"], "pages"), Some(1));
        assert!(router_root_index(&["app", "src", "pages"], "pages").is_none());
        assert_eq!(path_parts("a//b\\c/"), vec!["a", "b", "c"]);
        assert!(path_parts("").is_empty());
        assert_eq!(conventional_page_path(&["blog", "index.tsx"], "index"), "/blog");
        assert_eq!(conventional_page_path(&["blog", "post.tsx"], "post"), "/blog/post");
        assert_eq!(conventional_page_path(&["index.tsx"], "index"), "/");
        assert_eq!(segments_to_route_path(&[]), "/");
        assert_eq!(segments_to_route_path(&["a", "b"]), "/a/b");
        assert_eq!(owned_segments_to_route_path(&[]), "/");
        assert_eq!(
            owned_segments_to_route_path(&["a".to_string(), "b".to_string()]),
            "/a/b"
        );
    }

    #[test]
    fn framework_scope_lookup_prefers_a_scope_whose_directory_contains_the_file() {
        let scopes = vec![
            FileRouteScope {
                directory: PathBuf::from("apps/web"),
                frameworks: FileRouteFrameworks {
                    nextjs: true,
                    nuxt: false,
                    sveltekit: false,
                },
            },
            FileRouteScope {
                directory: PathBuf::new(),
                frameworks: FileRouteFrameworks {
                    nextjs: false,
                    nuxt: true,
                    sveltekit: false,
                },
            },
        ];
        let scoped = framework_scope_for_file("apps/web/pages/index.tsx", &scopes).expect("scoped");
        assert!(scoped.frameworks.nextjs);
        let root = framework_scope_for_file("pages/index.vue", &scopes).expect("root scope");
        assert!(root.frameworks.nuxt);
        assert!(framework_scope_for_file("a.ts", &[]).is_none());
    }

    #[test]
    fn package_json_framework_detection_reads_both_dependency_sections() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("package.json");
        std::fs::write(
            &path,
            r#"{"dependencies":{"next":"14"},"devDependencies":{"@sveltejs/kit":"2"}}"#,
        )
        .expect("package.json");
        let frameworks = package_json_frameworks(&path);
        assert!(frameworks.nextjs);
        assert!(frameworks.sveltekit);
        assert!(!frameworks.nuxt);

        std::fs::write(&path, r#"{"dependencies":{"nuxt":"3"}}"#).expect("package.json");
        assert!(package_json_frameworks(&path).nuxt);

        std::fs::write(&path, "{not json").expect("package.json");
        let none = package_json_frameworks(&path);
        assert!(!none.nextjs && !none.nuxt && !none.sveltekit);
        let absent = package_json_frameworks(&tmp.path().join("absent.json"));
        assert!(!absent.nextjs && !absent.nuxt && !absent.sveltekit);
    }
}
