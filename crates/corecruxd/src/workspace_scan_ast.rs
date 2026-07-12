// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `syn`-backed workspace scan implementation.
//!
//! This module preserves the `WorkspaceScan` wire shape owned by
//! `workspace_scan.rs`, but replaces the regex call/reference/dead-code pass
//! with a parsed Rust AST index.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::path::{Path, PathBuf};

use syn::visit::Visit;

use crate::workspace_scan::{
    parse_crate_name, parse_file_doc_header, parse_internal_path_deps, parse_routes_in_source, parse_stub_line,
    walk_dir, CrateInfo, DeadSymbol, DepEdge, FileInfo, FileReference, ParsedRoute, RouteHit, ScanDiagnostics,
    ScanError, ScanStats, StubHit, SymbolInfo, UnresolvedRoute, WorkspaceScan,
};

pub(crate) fn run_scan_ast_at(root: &Path) -> Result<WorkspaceScan, ScanError> {
    let started_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    let started_inst = std::time::Instant::now();
    let cache = AstScanCache::from_root(root)?;
    let mut scan = assemble_scan(root, &cache);
    reset_scan_start(&mut scan, started_ms);
    finish_scan_timing(&mut scan, started_inst);
    Ok(scan)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IncrementalUpdateStats {
    pub files_reparsed: usize,
    pub cache_hits: usize,
    pub files_dropped: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct IncrementalScanResult {
    pub scan: WorkspaceScan,
    pub stats: IncrementalUpdateStats,
}

#[derive(Debug, Clone)]
pub(crate) struct AstScanCache {
    pub root_path: PathBuf,
    crate_dirs: BTreeMap<String, PathBuf>,
    crate_internal_deps: BTreeMap<String, Vec<String>>,
    crate_order: Vec<String>,
    pub files: BTreeMap<String, CachedFile>,
}

#[derive(Debug, Clone)]
pub(crate) struct CachedFile {
    pub rel_path: String,
    pub crate_name: String,
    pub module_path: String,
    pub mtime_ms: u64,
    pub len: u64,
    pub content_hash: String,
    pub loc: usize,
    pub doc_summary: Option<String>,
    pub doc_full: Option<String>,
    pub is_test_file: bool,
    pub stubs: Vec<StubHit>,
    pub symbols: Vec<SymbolInfo>,
    fns: Vec<CachedFnDef>,
    deps: Vec<DepEdge>,
    routes: Vec<ParsedRoute>,
    ident_refs: HashMap<String, usize>,
}

#[derive(Debug, Clone)]
struct CachedFnDef {
    qualified: String,
    simple: String,
    crate_name: String,
    module_path: String,
    file: String,
    local_symbol_idx: usize,
    calls: Vec<CallRef>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileSignature {
    mtime_ms: u64,
    len: u64,
}

impl AstScanCache {
    pub(crate) fn from_root(root: &Path) -> Result<Self, ScanError> {
        let workspace = discover_workspace(root)?;
        let known_crate_names: BTreeSet<String> = workspace.crate_dirs.keys().cloned().collect();
        let mut files = BTreeMap::new();
        for (cname, crate_files) in &workspace.files_by_crate {
            let Some(crate_root) = workspace.crate_dirs.get(cname) else {
                continue;
            };
            for abs in crate_files {
                let cached = parse_file_ast(root, cname, crate_root, abs, &known_crate_names)?;
                files.insert(cached.rel_path.clone(), cached);
            }
        }
        Ok(Self {
            root_path: root.to_path_buf(),
            crate_dirs: workspace.crate_dirs,
            crate_internal_deps: workspace.crate_internal_deps,
            crate_order: workspace.files_by_crate.keys().cloned().collect(),
            files,
        })
    }
}

pub(crate) fn assemble_scan(root: &Path, cache: &AstScanCache) -> WorkspaceScan {
    let started_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    assemble_scan_at(root, cache, started_ms)
}

pub(crate) fn update_cache_incremental(
    root: &Path,
    cache: &mut AstScanCache,
    changed_paths: &[PathBuf],
) -> Result<IncrementalScanResult, ScanError> {
    let started_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    let started_inst = std::time::Instant::now();
    let stats = refresh_cache(root, cache, changed_paths)?;
    let mut scan = assemble_scan(root, cache);
    reset_scan_start(&mut scan, started_ms);
    finish_scan_timing(&mut scan, started_inst);
    Ok(IncrementalScanResult { scan, stats })
}

fn reset_scan_start(scan: &mut WorkspaceScan, started_ms: u64) {
    scan.scan_id = format!("ws_{started_ms}");
    scan.started_at_unix_ms = started_ms;
}

fn finish_scan_timing(scan: &mut WorkspaceScan, started_inst: std::time::Instant) {
    let elapsed_ms = started_inst.elapsed().as_millis() as u64;
    scan.finished_at_unix_ms = scan.started_at_unix_ms + elapsed_ms;
    scan.duration_ms = elapsed_ms;
}

fn assemble_scan_at(root: &Path, cache: &AstScanCache, started_ms: u64) -> WorkspaceScan {
    let mut scan = WorkspaceScan {
        scan_id: format!("ws_{started_ms}"),
        root_path: root.display().to_string(),
        started_at_unix_ms: started_ms,
        diagnostics: ScanDiagnostics::default(),
        ..Default::default()
    };
    let mut index = Index::default();
    let mut file_idx_by_path: HashMap<String, usize> = HashMap::new();
    let mut local_symbol_to_global: HashMap<(String, usize), usize> = HashMap::new();
    let mut ident_refs: HashMap<String, usize> = HashMap::new();

    for cname in &cache.crate_order {
        let Some(crate_root) = cache.crate_dirs.get(cname) else {
            continue;
        };
        let mut crate_loc = 0usize;
        let mut crate_file_count = 0usize;
        for file in cache.files.values().filter(|f| &f.crate_name == cname) {
            let file_idx = scan.files.len();
            file_idx_by_path.insert(file.rel_path.clone(), file_idx);
            crate_loc += file.loc;
            crate_file_count += 1;
            scan.files.push(FileInfo {
                rel_path: file.rel_path.clone(),
                crate_name: file.crate_name.clone(),
                module_path: file.module_path.clone(),
                loc: file.loc,
                symbol_count: file.symbols.len(),
                stub_count: file.stubs.len(),
                doc_summary: file.doc_summary.clone(),
                doc_full: file.doc_full.clone(),
                defines: Vec::new(),
                references: Vec::new(),
                referenced_by: Vec::new(),
                is_test_file: file.is_test_file,
            });
            scan.stubs.extend(file.stubs.iter().cloned());
            scan.deps.extend(file.deps.iter().cloned());
            for (local_idx, symbol) in file.symbols.iter().cloned().enumerate() {
                let global_idx = scan.symbols.len();
                scan.symbols.push(symbol);
                local_symbol_to_global.insert((file.rel_path.clone(), local_idx), global_idx);
            }
            for (ident, count) in &file.ident_refs {
                *ident_refs.entry(ident.clone()).or_insert(0) += *count;
            }
        }
        scan.crates.push(CrateInfo {
            name: cname.clone(),
            rel_path: crate_root
                .strip_prefix(root)
                .map_or_else(|_| crate_root.display().to_string(), |p| p.display().to_string()),
            internal_deps: cache.crate_internal_deps.get(cname).cloned().unwrap_or_default(),
            file_count: crate_file_count,
            total_loc: crate_loc,
        });
    }

    for file in cache.files.values() {
        for def in &file.fns {
            let Some(symbol_idx) = local_symbol_to_global
                .get(&(file.rel_path.clone(), def.local_symbol_idx))
                .copied()
            else {
                continue;
            };
            index.push(FnDef {
                qualified: def.qualified.clone(),
                simple: def.simple.clone(),
                crate_name: def.crate_name.clone(),
                module_path: def.module_path.clone(),
                file: def.file.clone(),
                symbol_idx,
                calls: def.calls.clone(),
            });
        }
    }

    denormalize_defines(&mut scan, &file_idx_by_path);
    resolve_routes_from_cache(cache, &index, &mut scan);
    resolve_references(&mut scan, &index, &file_idx_by_path);
    build_referenced_by(&mut scan);
    compute_dead_code(&mut scan, &ident_refs);
    crate::workspace_scan_manifests::attach_external_deps_if_enabled(root, &mut scan);
    roll_up_stats(&mut scan);
    scan
}

fn refresh_cache(
    root: &Path,
    cache: &mut AstScanCache,
    changed_paths: &[PathBuf],
) -> Result<IncrementalUpdateStats, ScanError> {
    let workspace = discover_workspace(root)?;
    let known_crate_names: BTreeSet<String> = workspace.crate_dirs.keys().cloned().collect();
    cache.root_path = root.to_path_buf();
    cache.crate_dirs = workspace.crate_dirs.clone();
    cache.crate_internal_deps = workspace.crate_internal_deps.clone();
    cache.crate_order = workspace.files_by_crate.keys().cloned().collect();

    let changed: BTreeSet<PathBuf> = changed_paths.iter().map(|p| absolutize(root, p)).collect();
    let mut current = BTreeSet::new();
    let mut stats = IncrementalUpdateStats {
        files_reparsed: 0,
        cache_hits: 0,
        files_dropped: 0,
    };

    for (cname, files) in &workspace.files_by_crate {
        let Some(crate_root) = workspace.crate_dirs.get(cname) else {
            continue;
        };
        for abs in files {
            let rel = rel_string(root, abs);
            if !is_rs_path(abs) || should_ignore_path(Path::new(&rel)) {
                continue;
            }
            current.insert(rel.clone());
            let signature = file_signature(abs)?;
            let changed_explicitly = changed.contains(&absolutize(root, abs));
            if let Some(cached) = cache.files.get(&rel) {
                if cached.mtime_ms == signature.mtime_ms && cached.len == signature.len {
                    if changed_explicitly {
                        let src = std::fs::read(abs).unwrap_or_default();
                        let content_hash = blake3::hash(&src).to_hex().to_string();
                        if content_hash != cached.content_hash {
                            let cached = parse_file_ast(root, cname, crate_root, abs, &known_crate_names)?;
                            cache.files.insert(rel, cached);
                            stats.files_reparsed += 1;
                            continue;
                        }
                    }
                    stats.cache_hits += 1;
                    continue;
                }
            }
            let cached = parse_file_ast(root, cname, crate_root, abs, &known_crate_names)?;
            cache.files.insert(rel, cached);
            stats.files_reparsed += 1;
        }
    }

    let stale: Vec<String> = cache
        .files
        .keys()
        .filter(|rel| !current.contains(*rel))
        .cloned()
        .collect();
    for rel in stale {
        cache.files.remove(&rel);
        stats.files_dropped += 1;
    }
    Ok(stats)
}

#[derive(Default)]
struct WorkspaceFiles {
    crate_dirs: BTreeMap<String, PathBuf>,
    crate_internal_deps: BTreeMap<String, Vec<String>>,
    files_by_crate: BTreeMap<String, Vec<PathBuf>>,
}

fn discover_workspace(root: &Path) -> Result<WorkspaceFiles, ScanError> {
    let mut cargo_files = Vec::new();
    walk_dir(root, root, &mut |rel_path, abs_path| {
        if abs_path.file_name().and_then(|n| n.to_str()) == Some("Cargo.toml") && rel_path != Path::new("Cargo.toml") {
            cargo_files.push(abs_path.to_path_buf());
        }
    })?;
    cargo_files.sort();

    let mut out = WorkspaceFiles::default();
    for cargo in &cargo_files {
        let crate_dir = cargo.parent().unwrap_or(root).to_path_buf();
        let toml = std::fs::read_to_string(cargo).unwrap_or_default();
        let name = parse_crate_name(&toml).unwrap_or_else(|| {
            crate_dir
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("?")
                .to_string()
        });
        out.crate_internal_deps
            .insert(name.clone(), parse_internal_path_deps(&toml));
        out.crate_dirs.insert(name, crate_dir);
    }

    for (name, dir) in &out.crate_dirs {
        let src = dir.join("src");
        if !src.exists() {
            continue;
        }
        let mut files = Vec::new();
        walk_dir(&src, &src, &mut |_rel, abs| {
            if abs.extension().and_then(|e| e.to_str()) == Some("rs") {
                files.push(abs.to_path_buf());
            }
        })?;
        files.sort();
        out.files_by_crate.insert(name.clone(), files);
    }
    Ok(out)
}

#[derive(Clone, Copy)]
struct FileCtx<'a> {
    crate_name: &'a str,
    crate_root: &'a Path,
    rel_path: &'a str,
    module_path: &'a str,
}

#[derive(Default)]
struct ParsedFileParts {
    symbols: Vec<SymbolInfo>,
    fns: Vec<CachedFnDef>,
    deps: Vec<DepEdge>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CallKind {
    Func,
    Method,
    Macro,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CallRef {
    segs: Vec<String>,
    kind: CallKind,
}

#[derive(Debug, Clone)]
struct FnDef {
    qualified: String,
    simple: String,
    crate_name: String,
    module_path: String,
    file: String,
    symbol_idx: usize,
    calls: Vec<CallRef>,
}

#[derive(Default)]
struct Index {
    defs: Vec<FnDef>,
    by_simple: BTreeMap<String, Vec<usize>>,
    by_qualified: BTreeMap<String, usize>,
    by_suffix: BTreeMap<String, Vec<usize>>,
}

impl Index {
    fn push(&mut self, def: FnDef) {
        let idx = self.defs.len();
        self.by_simple.entry(def.simple.clone()).or_default().push(idx);
        self.by_qualified.insert(def.qualified.clone(), idx);
        let parts: Vec<&str> = def.qualified.split("::").collect();
        for start in 0..parts.len().saturating_sub(1) {
            self.by_suffix.entry(parts[start..].join("::")).or_default().push(idx);
        }
        self.defs.push(def);
    }

    fn resolve(&self, call: &CallRef, from: &FnDef) -> Option<usize> {
        if call.kind != CallKind::Func {
            return None;
        }
        let segs = normalize_call_segs(&call.segs, from);
        if segs.is_empty() {
            return None;
        }
        if segs.len() >= 2 {
            let suffix = segs.join("::");
            return match self.by_suffix.get(&suffix).map(Vec::as_slice) {
                Some([one]) => Some(*one),
                _ => None,
            };
        }

        let simple = segs[0].clone();
        let candidates = self.by_simple.get(&simple)?;
        let current_module = format!("{}::{}", from.module_path, simple);
        let same_module: Vec<usize> = candidates
            .iter()
            .copied()
            .filter(|idx| self.defs[*idx].qualified == current_module)
            .collect();
        if let [one] = same_module.as_slice() {
            return Some(*one);
        }

        let same_file: Vec<usize> = candidates
            .iter()
            .copied()
            .filter(|idx| self.defs[*idx].file == from.file)
            .collect();
        if let [one] = same_file.as_slice() {
            return Some(*one);
        }

        let same_crate: Vec<usize> = candidates
            .iter()
            .copied()
            .filter(|idx| self.defs[*idx].crate_name == from.crate_name)
            .collect();
        if let [one] = same_crate.as_slice() {
            return Some(*one);
        }

        match candidates.as_slice() {
            [one] => Some(*one),
            _ => None,
        }
    }
}

struct CallCollector {
    calls: Vec<CallRef>,
}

impl<'ast> Visit<'ast> for CallCollector {
    fn visit_expr_call(&mut self, c: &'ast syn::ExprCall) {
        if let syn::Expr::Path(p) = &*c.func {
            let segs: Vec<String> = p.path.segments.iter().map(|s| s.ident.to_string()).collect();
            if !segs.is_empty() {
                self.calls.push(CallRef {
                    segs,
                    kind: CallKind::Func,
                });
            }
        }
        syn::visit::visit_expr_call(self, c);
    }

    fn visit_expr_method_call(&mut self, m: &'ast syn::ExprMethodCall) {
        self.calls.push(CallRef {
            segs: vec![m.method.to_string()],
            kind: CallKind::Method,
        });
        syn::visit::visit_expr_method_call(self, m);
    }

    fn visit_macro(&mut self, m: &'ast syn::Macro) {
        if let Some(seg) = m.path.segments.last() {
            self.calls.push(CallRef {
                segs: vec![seg.ident.to_string()],
                kind: CallKind::Macro,
            });
        }
        syn::visit::visit_macro(self, m);
    }
}

fn collect_calls(block: &syn::Block) -> Vec<CallRef> {
    let mut collector = CallCollector { calls: Vec::new() };
    collector.visit_block(block);
    collector.calls
}

#[derive(Default)]
struct IdentRefCollector {
    counts: HashMap<String, usize>,
}

impl<'ast> Visit<'ast> for IdentRefCollector {
    fn visit_path(&mut self, path: &'ast syn::Path) {
        for seg in &path.segments {
            self.bump(seg.ident.to_string());
        }
        syn::visit::visit_path(self, path);
    }

    fn visit_expr_method_call(&mut self, m: &'ast syn::ExprMethodCall) {
        self.bump(m.method.to_string());
        syn::visit::visit_expr_method_call(self, m);
    }

    fn visit_macro(&mut self, m: &'ast syn::Macro) {
        for seg in &m.path.segments {
            self.bump(seg.ident.to_string());
        }
        syn::visit::visit_macro(self, m);
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        self.visit_use_tree_idents(&item.tree);
        syn::visit::visit_item_use(self, item);
    }
}

impl IdentRefCollector {
    fn bump(&mut self, ident: String) {
        *self.counts.entry(ident).or_insert(0) += 1;
    }

    fn visit_use_tree_idents(&mut self, tree: &syn::UseTree) {
        match tree {
            syn::UseTree::Path(p) => {
                self.bump(p.ident.to_string());
                self.visit_use_tree_idents(&p.tree);
            }
            syn::UseTree::Name(n) => self.bump(n.ident.to_string()),
            syn::UseTree::Rename(r) => self.bump(r.ident.to_string()),
            syn::UseTree::Glob(_) => {}
            syn::UseTree::Group(g) => {
                for item in &g.items {
                    self.visit_use_tree_idents(item);
                }
            }
        }
    }
}

fn collect_identifier_refs(file: &syn::File, into: &mut HashMap<String, usize>) {
    let mut collector = IdentRefCollector::default();
    collector.visit_file(file);
    for (ident, count) in collector.counts {
        *into.entry(ident).or_insert(0) += count;
    }
}

fn parse_file_ast(
    root: &Path,
    crate_name: &str,
    crate_root: &Path,
    abs: &Path,
    known_crates: &BTreeSet<String>,
) -> Result<CachedFile, ScanError> {
    let rel_str = rel_string(root, abs);
    let module_path = crate::workspace_scan::infer_module_path(crate_name, crate_root, abs);
    let src = std::fs::read_to_string(abs).unwrap_or_default();
    let signature = file_signature(abs)?;
    let loc = src.lines().count();
    let content_hash = blake3::hash(src.as_bytes()).to_hex().to_string();
    let (doc_full, doc_summary) = parse_file_doc_header(&src);
    let is_test_file = crate::workspace_scan::looks_like_test_file(&rel_str, &src);
    let mut stubs = Vec::new();
    let is_scanner_source = rel_str.ends_with("corecruxd/src/workspace_scan.rs")
        || rel_str.ends_with("corecruxd/src/workspace_scan_ast.rs");
    if !is_scanner_source {
        for (line_no, line) in src.lines().enumerate() {
            if let Some((kind, snippet)) = parse_stub_line(line) {
                stubs.push(StubHit {
                    crate_name: crate_name.to_string(),
                    file_rel_path: rel_str.clone(),
                    line: line_no + 1,
                    kind: kind.to_string(),
                    snippet,
                });
            }
        }
    }

    let mut parts = ParsedFileParts::default();
    if let Ok(parsed) = syn::parse_file(&src) {
        let mut ident_refs = HashMap::new();
        collect_identifier_refs(&parsed, &mut ident_refs);
        let mut line_lookup = LineLookup::new(&src);
        index_items(
            &mut parts,
            known_crates,
            &mut line_lookup,
            &parsed.items,
            FileCtx {
                crate_name,
                crate_root,
                rel_path: &rel_str,
                module_path: &module_path,
            },
        );
        Ok(CachedFile {
            rel_path: rel_str.clone(),
            crate_name: crate_name.to_string(),
            module_path,
            mtime_ms: signature.mtime_ms,
            len: signature.len,
            content_hash,
            loc,
            doc_summary,
            doc_full,
            is_test_file,
            stubs,
            symbols: parts.symbols,
            fns: parts.fns,
            deps: parts.deps,
            routes: parse_routes_in_source(&src, &rel_str),
            ident_refs,
        })
    } else {
        Ok(CachedFile {
            rel_path: rel_str.clone(),
            crate_name: crate_name.to_string(),
            module_path,
            mtime_ms: signature.mtime_ms,
            len: signature.len,
            content_hash,
            loc,
            doc_summary,
            doc_full,
            is_test_file,
            stubs,
            symbols: Vec::new(),
            fns: Vec::new(),
            deps: Vec::new(),
            routes: parse_routes_in_source(&src, &rel_str),
            ident_refs: HashMap::new(),
        })
    }
}

fn index_items(
    parts: &mut ParsedFileParts,
    known_crates: &BTreeSet<String>,
    line_lookup: &mut LineLookup,
    items: &[syn::Item],
    ctx: FileCtx<'_>,
) {
    for item in items {
        match item {
            syn::Item::Fn(f) => {
                let name = f.sig.ident.to_string();
                let local_symbol_idx = push_symbol(parts, ctx, line_lookup, "fn", &name, is_pub(&f.vis));
                parts.fns.push(CachedFnDef {
                    qualified: qualify(ctx.module_path, &name),
                    simple: name,
                    crate_name: ctx.crate_name.to_string(),
                    module_path: ctx.module_path.to_string(),
                    file: ctx.rel_path.to_string(),
                    local_symbol_idx,
                    calls: collect_calls(&f.block),
                });
            }
            syn::Item::Struct(s) => {
                let name = s.ident.to_string();
                push_symbol(parts, ctx, line_lookup, "struct", &name, is_pub(&s.vis));
            }
            syn::Item::Enum(e) => {
                let name = e.ident.to_string();
                push_symbol(parts, ctx, line_lookup, "enum", &name, is_pub(&e.vis));
            }
            syn::Item::Trait(t) => {
                let name = t.ident.to_string();
                push_symbol(parts, ctx, line_lookup, "trait", &name, is_pub(&t.vis));
            }
            syn::Item::Type(t) => {
                let name = t.ident.to_string();
                push_symbol(parts, ctx, line_lookup, "type", &name, is_pub(&t.vis));
            }
            syn::Item::Const(c) => {
                let name = c.ident.to_string();
                push_symbol(parts, ctx, line_lookup, "const", &name, is_pub(&c.vis));
            }
            syn::Item::Static(s) => {
                let name = s.ident.to_string();
                push_symbol(parts, ctx, line_lookup, "static", &name, is_pub(&s.vis));
            }
            syn::Item::Mod(m) => {
                let name = m.ident.to_string();
                push_symbol(parts, ctx, line_lookup, "mod", &name, is_pub(&m.vis));
                if let Some((_, inner)) = &m.content {
                    let nested = qualify(ctx.module_path, &name);
                    let nested_ctx = FileCtx {
                        module_path: &nested,
                        ..ctx
                    };
                    index_items(parts, known_crates, line_lookup, inner, nested_ctx);
                }
            }
            syn::Item::Impl(im) => {
                let ty = impl_type_name(&im.self_ty);
                let impl_base = ty
                    .as_deref()
                    .map_or_else(|| ctx.module_path.to_string(), |t| qualify(ctx.module_path, t));
                for ii in &im.items {
                    if let syn::ImplItem::Fn(f) = ii {
                        let name = f.sig.ident.to_string();
                        let local_symbol_idx = push_symbol(parts, ctx, line_lookup, "fn", &name, is_pub(&f.vis));
                        parts.fns.push(CachedFnDef {
                            qualified: qualify(&impl_base, &name),
                            simple: name,
                            crate_name: ctx.crate_name.to_string(),
                            module_path: ctx.module_path.to_string(),
                            file: ctx.rel_path.to_string(),
                            local_symbol_idx,
                            calls: collect_calls(&f.block),
                        });
                    }
                }
            }
            syn::Item::Use(u) => {
                for raw in use_tree_paths(&u.tree) {
                    if let Some(to_module) = use_path_to_module(&raw, ctx.crate_name, known_crates) {
                        parts.deps.push(DepEdge {
                            from_crate: ctx.crate_name.to_string(),
                            from_file: ctx.rel_path.to_string(),
                            to_module,
                            raw: format!("use {raw};"),
                        });
                    }
                }
            }
            _ => {}
        }
    }

    let _ = ctx.crate_root;
}

fn push_symbol(
    parts: &mut ParsedFileParts,
    ctx: FileCtx<'_>,
    line_lookup: &mut LineLookup,
    kind: &str,
    name: &str,
    is_pub: bool,
) -> usize {
    let symbol_idx = parts.symbols.len();
    parts.symbols.push(SymbolInfo {
        crate_name: ctx.crate_name.to_string(),
        module_path: ctx.module_path.to_string(),
        file_rel_path: ctx.rel_path.to_string(),
        line: line_lookup.take(kind, name),
        kind: kind.to_string(),
        name: name.to_string(),
        is_pub,
    });
    symbol_idx
}

struct LineLookup {
    by_kind_name: HashMap<(String, String), VecDeque<usize>>,
}

impl LineLookup {
    fn new(src: &str) -> Self {
        let mut by_kind_name: HashMap<(String, String), VecDeque<usize>> = HashMap::new();
        for (idx, line) in src.lines().enumerate() {
            if let Some((kind, name)) = parse_decl_line(line) {
                by_kind_name
                    .entry((kind.to_string(), name))
                    .or_default()
                    .push_back(idx + 1);
            }
        }
        Self { by_kind_name }
    }

    fn take(&mut self, kind: &str, name: &str) -> usize {
        self.by_kind_name
            .get_mut(&(kind.to_string(), name.to_string()))
            .and_then(VecDeque::pop_front)
            .unwrap_or(0)
    }
}

fn parse_decl_line(line: &str) -> Option<(&'static str, String)> {
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") {
        return None;
    }
    let rest = trimmed
        .strip_prefix("pub ")
        .or_else(|| trimmed.strip_prefix("pub(crate) "))
        .or_else(|| trimmed.strip_prefix("pub(super) "))
        .unwrap_or(trimmed);
    let kinds: &[(&str, &str)] = &[
        ("async fn ", "fn"),
        ("unsafe fn ", "fn"),
        ("const fn ", "fn"),
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
                return Some((*kind, name));
            }
        }
    }
    None
}

fn is_pub(vis: &syn::Visibility) -> bool {
    matches!(vis, syn::Visibility::Public(_) | syn::Visibility::Restricted(_))
}

fn qualify(base: &str, name: &str) -> String {
    if base.is_empty() {
        name.to_string()
    } else {
        format!("{base}::{name}")
    }
}

fn impl_type_name(ty: &syn::Type) -> Option<String> {
    if let syn::Type::Path(p) = ty {
        p.path.segments.last().map(|s| s.ident.to_string())
    } else {
        None
    }
}

fn use_tree_paths(tree: &syn::UseTree) -> Vec<String> {
    fn walk(prefix: &mut Vec<String>, tree: &syn::UseTree, out: &mut Vec<String>) {
        match tree {
            syn::UseTree::Path(p) => {
                prefix.push(p.ident.to_string());
                walk(prefix, &p.tree, out);
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
                    walk(prefix, item, out);
                }
            }
        }
    }
    let mut out = Vec::new();
    walk(&mut Vec::new(), tree, &mut out);
    out
}

fn use_path_to_module(raw: &str, from_crate: &str, known_crates: &BTreeSet<String>) -> Option<String> {
    let first = raw.split("::").next().unwrap_or("");
    if first == "crate" || first == "self" || first == "super" {
        return Some(format!("{}::{}", from_crate.replace('-', "_"), raw));
    }
    let first_norm = first.replace('_', "-");
    if known_crates.contains(first) || known_crates.contains(&first_norm) {
        return Some(raw.to_string());
    }
    None
}

fn rel_string(root: &Path, abs: &Path) -> String {
    abs.strip_prefix(root)
        .map_or_else(|_| abs.to_path_buf(), Path::to_path_buf)
        .display()
        .to_string()
}

fn absolutize(root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

fn file_signature(path: &Path) -> Result<FileSignature, ScanError> {
    let metadata = std::fs::metadata(path)?;
    let mtime_ms = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_millis() as u64);
    Ok(FileSignature {
        mtime_ms,
        len: metadata.len(),
    })
}

fn is_rs_path(path: &Path) -> bool {
    path.extension().and_then(|e| e.to_str()) == Some("rs")
}

pub(crate) fn should_ignore_path(path: &Path) -> bool {
    path.components().any(|component| {
        let name = component.as_os_str().to_string_lossy();
        name.starts_with('.') || matches!(name.as_ref(), "target" | "node_modules" | ".git" | ".worktrees")
    })
}

fn normalize_call_segs(segs: &[String], from: &FnDef) -> Vec<String> {
    if segs.is_empty() {
        return Vec::new();
    }
    let first = segs[0].as_str();
    match first {
        "crate" => {
            let mut out = vec![from.crate_name.replace('-', "_")];
            out.extend(segs.iter().skip(1).cloned());
            out
        }
        "self" => {
            let mut out: Vec<String> = from.module_path.split("::").map(ToString::to_string).collect();
            out.extend(segs.iter().skip(1).cloned());
            out
        }
        "super" => {
            let mut out: Vec<String> = from.module_path.split("::").map(ToString::to_string).collect();
            out.pop();
            out.extend(segs.iter().skip(1).cloned());
            out
        }
        _ => segs.iter().map(|s| s.replace('-', "_")).collect(),
    }
}

fn denormalize_defines(scan: &mut WorkspaceScan, file_idx_by_path: &HashMap<String, usize>) {
    for s in &scan.symbols {
        if let Some(idx) = file_idx_by_path.get(&s.file_rel_path) {
            let f = &mut scan.files[*idx];
            if !f.defines.contains(&s.name) {
                f.defines.push(s.name.clone());
            }
        }
    }
}

fn resolve_routes_from_cache(cache: &AstScanCache, index: &Index, scan: &mut WorkspaceScan) {
    for file in cache.files.values() {
        for route in &file.routes {
            let mut resolved_file = None;
            let mut resolved_line = None;
            let mut diag_reason = None;
            match index.by_simple.get(&route.handler_fn) {
                None => diag_reason = Some("not_found"),
                Some(candidates) => {
                    let same_crate: Vec<usize> = candidates
                        .iter()
                        .copied()
                        .filter(|idx| index.defs[*idx].crate_name == file.crate_name)
                        .collect();
                    let pick = if let [one] = same_crate.as_slice() {
                        Some(*one)
                    } else if let [one] = candidates.as_slice() {
                        Some(*one)
                    } else {
                        None
                    };
                    if let Some(def_idx) = pick {
                        let sym = &scan.symbols[index.defs[def_idx].symbol_idx];
                        resolved_file = Some(sym.file_rel_path.clone());
                        resolved_line = Some(sym.line);
                    } else {
                        diag_reason = Some("ambiguous");
                    }
                }
            }
            if let Some(reason) = diag_reason {
                scan.diagnostics.unresolved_routes.push(UnresolvedRoute {
                    method: route.method.clone(),
                    path: route.path.clone(),
                    handler_fn: route.handler_fn.clone(),
                    source_file: route.source_file.clone(),
                    source_line: route.source_line,
                    reason: reason.to_string(),
                });
            }
            scan.routes.push(RouteHit {
                method: route.method.clone(),
                path: route.path.clone(),
                handler_fn: route.handler_fn.clone(),
                framework: None,
                handler_file: resolved_file,
                handler_line: resolved_line,
                source_file: route.source_file.clone(),
                source_line: route.source_line,
            });
        }
    }
}

fn resolve_references(scan: &mut WorkspaceScan, index: &Index, file_idx_by_path: &HashMap<String, usize>) {
    type EdgeKey = (String, String, String);
    let mut per_file_edges: HashMap<usize, BTreeMap<EdgeKey, usize>> = HashMap::new();
    for from in &index.defs {
        let Some(from_idx) = file_idx_by_path.get(&from.file).copied() else {
            continue;
        };
        for call in &from.calls {
            let Some(target_idx) = index.resolve(call, from) else {
                continue;
            };
            let target = &scan.symbols[index.defs[target_idx].symbol_idx];
            let key = (target.file_rel_path.clone(), target.name.clone(), from.simple.clone());
            *per_file_edges.entry(from_idx).or_default().entry(key).or_insert(0) += 1;
        }
    }

    for (from_idx, edges) in per_file_edges {
        let from_path = scan.files[from_idx].rel_path.clone();
        for ((to_file, to_symbol, from_symbol), call_count) in edges {
            scan.files[from_idx].references.push(FileReference {
                same_file: to_file == from_path,
                to_file,
                to_symbol,
                call_count,
                from_symbol: Some(from_symbol),
            });
        }
    }
}

fn build_referenced_by(scan: &mut WorkspaceScan) {
    let mut inverse: HashMap<String, BTreeSet<String>> = HashMap::new();
    for f in &scan.files {
        for r in &f.references {
            if !r.same_file {
                inverse.entry(r.to_file.clone()).or_default().insert(f.rel_path.clone());
            }
        }
    }
    for f in &mut scan.files {
        if let Some(set) = inverse.remove(&f.rel_path) {
            f.referenced_by = set.into_iter().collect();
        }
    }
}

fn compute_dead_code(scan: &mut WorkspaceScan, ident_refs: &HashMap<String, usize>) {
    let common_names: BTreeSet<&str> = [
        "new", "default", "len", "is_empty", "from", "into", "as_str", "as_ref", "clone", "drop", "fmt", "next",
        "iter", "build", "ok", "err", "some", "none", "main", "init",
    ]
    .iter()
    .copied()
    .collect();
    for sym in &scan.symbols {
        if !sym.is_pub || sym.name.starts_with('_') {
            continue;
        }
        if sym.name.len() < 4 {
            continue;
        }
        if common_names.contains(sym.name.as_str()) {
            continue;
        }
        if ident_refs.get(&sym.name).copied().unwrap_or(0) == 0 {
            scan.dead_code.push(DeadSymbol {
                crate_name: sym.crate_name.clone(),
                module_path: sym.module_path.clone(),
                file_rel_path: sym.file_rel_path.clone(),
                line: sym.line,
                kind: sym.kind.clone(),
                name: sym.name.clone(),
                confidence: 0.75,
                note: "no workspace-wide AST references (ast-ident-reachability)".to_string(),
            });
        }
    }
}

fn roll_up_stats(scan: &mut WorkspaceScan) {
    let route_count = scan.routes.len();
    let file_reference_count = scan.files.iter().map(|f| f.references.len()).sum();
    let doc_coverage_files = scan.files.iter().filter(|f| f.doc_summary.is_some()).count();
    let mut routes_by_crate = BTreeMap::new();
    for r in &scan.routes {
        if let Some(hf) = &r.handler_file {
            for c in &scan.crates {
                if hf.starts_with(&format!("{}/", c.rel_path)) {
                    *routes_by_crate.entry(c.name.clone()).or_insert(0) += 1;
                    break;
                }
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
        route_count,
        file_reference_count,
        external_dep_count: scan.external_deps.len(),
        doc_coverage_files,
        routes_by_crate,
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::EnvVarGuard;

    fn write_fixture(root: &Path) {
        let crate_dir = root.join("crates/demo");
        std::fs::create_dir_all(crate_dir.join("src")).expect("fixture dirs");
        std::fs::write(root.join("Cargo.toml"), "[workspace]\nmembers = [\"crates/demo\"]\n").expect("workspace toml");
        std::fs::write(
            crate_dir.join("Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .expect("crate toml");
        std::fs::write(
            crate_dir.join("src/lib.rs"),
            r#"//! Demo crate.

pub mod a;
pub mod b;
pub struct Visible;
pub struct UnusedStruct;
"#,
        )
        .expect("lib");
        std::fs::write(
            crate_dir.join("src/a.rs"),
            r#"//! A module.
use crate::b::called;

pub fn entry() {
    crate::b::called();
}

pub fn dead_pub() {}
fn takes_visible(_: crate::Visible) {}
fn private_helper() {}
"#,
        )
        .expect("a");
        std::fs::write(
            crate_dir.join("src/b.rs"),
            r#"//! B module.
pub fn called() {}
"#,
        )
        .expect("b");
    }

    #[test]
    fn ast_fixture_resolves_symbols_cross_file_call_and_dead_symbol() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_fixture(tmp.path());
        let scan = run_scan_ast_at(tmp.path()).expect("ast scan");

        assert!(scan
            .symbols
            .iter()
            .any(|s| s.name == "entry" && s.kind == "fn" && s.is_pub && s.line == 4));
        assert!(scan
            .symbols
            .iter()
            .any(|s| s.name == "Visible" && s.kind == "struct" && s.is_pub));

        let a = scan
            .files
            .iter()
            .find(|f| f.rel_path.ends_with("crates/demo/src/a.rs"))
            .expect("a.rs");
        assert!(
            a.references.iter().any(|r| r.to_file.ends_with("crates/demo/src/b.rs")
                && r.to_symbol == "called"
                && r.call_count == 1
                && r.from_symbol.as_deref() == Some("entry")),
            "expected cross-file edge from a::entry to b::called: {:?}",
            a.references
        );

        assert!(scan
            .dead_code
            .iter()
            .any(|d| d.name == "dead_pub" && d.note.contains("ast-ident-reachability")));
        assert!(scan.dead_code.iter().any(|d| d.name == "UnusedStruct"));
        assert!(!scan.dead_code.iter().any(|d| d.name == "Visible"));
        assert!(!scan.dead_code.iter().any(|d| d.name == "called"));
    }

    fn normalize_scan(mut scan: WorkspaceScan) -> WorkspaceScan {
        scan.scan_id.clear();
        scan.started_at_unix_ms = 0;
        scan.finished_at_unix_ms = 0;
        scan.duration_ms = 0;
        scan
    }

    fn append_external_dep_fixture(root: &Path) {
        let manifest = root.join("crates/demo/Cargo.toml");
        let mut current = std::fs::read_to_string(&manifest).expect("read manifest");
        current.push_str("\n[dependencies]\nserde = \"1\"\n");
        std::fs::write(&manifest, current).expect("write manifest");
    }

    #[test]
    fn incremental_reparse_only_changed_file_and_updates_symbol_edge() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_fixture(tmp.path());
        let mut cache = AstScanCache::from_root(tmp.path()).expect("full cache");
        let total = cache.files.len();
        let changed = tmp.path().join("crates/demo/src/a.rs");
        std::fs::write(
            &changed,
            r#"//! A module.
use crate::b::called;

pub fn entry() {
    crate::b::called();
}

pub fn new_entry() {
    crate::b::called();
}

pub fn dead_pub() {}
fn takes_visible(_: crate::Visible) {}
fn private_helper() {}
"#,
        )
        .expect("rewrite changed file");

        let result = update_cache_incremental(tmp.path(), &mut cache, std::slice::from_ref(&changed))
            .expect("incremental update");
        assert_eq!(result.stats.files_reparsed, 1);
        assert_eq!(result.stats.cache_hits, total - 1);
        assert_eq!(result.stats.files_dropped, 0);
        assert!(result
            .scan
            .symbols
            .iter()
            .any(|s| s.name == "new_entry" && s.kind == "fn"));
        let a = result
            .scan
            .files
            .iter()
            .find(|f| f.rel_path.ends_with("crates/demo/src/a.rs"))
            .expect("a.rs");
        assert!(a.references.iter().any(|r| {
            r.to_file.ends_with("crates/demo/src/b.rs")
                && r.to_symbol == "called"
                && r.from_symbol.as_deref() == Some("new_entry")
        }));
    }

    #[test]
    fn incremental_delete_drops_symbols_and_edges() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_fixture(tmp.path());
        let mut cache = AstScanCache::from_root(tmp.path()).expect("full cache");
        let deleted = tmp.path().join("crates/demo/src/b.rs");
        std::fs::remove_file(&deleted).expect("delete b.rs");

        let result = update_cache_incremental(tmp.path(), &mut cache, std::slice::from_ref(&deleted))
            .expect("incremental delete");
        assert_eq!(result.stats.files_dropped, 1);
        assert!(!result
            .scan
            .symbols
            .iter()
            .any(|s| s.file_rel_path.ends_with("crates/demo/src/b.rs")));
        assert!(!result
            .scan
            .files
            .iter()
            .any(|f| f.rel_path.ends_with("crates/demo/src/b.rs")));
        assert!(!result
            .scan
            .files
            .iter()
            .flat_map(|f| &f.references)
            .any(|r| { r.to_file.ends_with("crates/demo/src/b.rs") || r.to_symbol == "called" }));
    }

    #[test]
    #[serial_test::serial]
    fn flag_off_ast_scan_serializes_without_external_dependency_fields() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_fixture(tmp.path());
        append_external_dep_fixture(tmp.path());

        let _env = EnvVarGuard::unset("CORECRUXD_EXTERNAL_DEPS");
        let scan = run_scan_ast_at(tmp.path()).expect("ast scan");
        let json = serde_json::to_string(&scan).expect("scan json");
        assert!(!json.contains("external_deps"));
        assert!(!json.contains("external_dep_count"));
    }

    #[test]
    #[serial_test::serial]
    fn watch_reindex_preserves_external_deps() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_fixture(tmp.path());
        append_external_dep_fixture(tmp.path());

        let _env = EnvVarGuard::set("CORECRUXD_EXTERNAL_DEPS", "1");
        let initial = run_scan_ast_at(tmp.path()).expect("initial scan");
        assert!(!initial.external_deps.is_empty());
        assert_eq!(initial.stats.external_dep_count, initial.external_deps.len());

        let mut cache = AstScanCache::from_root(tmp.path()).expect("full cache");
        let changed = tmp.path().join("crates/demo/src/a.rs");
        std::fs::write(
            &changed,
            r#"//! A module.
use crate::b::called;

pub fn entry() {
    crate::b::called();
}

pub fn dead_pub() {}
fn takes_visible(_: crate::Visible) {}
fn private_helper() {}
"#,
        )
        .expect("rewrite changed file");
        let result = update_cache_incremental(tmp.path(), &mut cache, std::slice::from_ref(&changed))
            .expect("incremental update");
        assert_eq!(result.scan.external_deps, initial.external_deps);
        assert_eq!(result.scan.stats.external_dep_count, result.scan.external_deps.len());
    }

    #[test]
    #[serial_test::serial]
    fn assemble_from_cache_matches_fresh_ast_scan() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_fixture(tmp.path());
        append_external_dep_fixture(tmp.path());
        let _env = EnvVarGuard::set("CORECRUXD_EXTERNAL_DEPS", "1");
        let cache = AstScanCache::from_root(tmp.path()).expect("full cache");
        let assembled = normalize_scan(assemble_scan(tmp.path(), &cache));
        let fresh = normalize_scan(run_scan_ast_at(tmp.path()).expect("fresh scan"));
        assert!(!assembled.external_deps.is_empty());
        assert_eq!(assembled.stats.external_dep_count, assembled.external_deps.len());
        assert_eq!(
            serde_json::to_value(assembled).expect("assembled json"),
            serde_json::to_value(fresh).expect("fresh json")
        );
    }
}
