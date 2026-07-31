// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

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
    let mut scan = assemble_scan(root, &cache)?;
    reset_scan_start(&mut scan, started_ms);
    finish_scan_timing(&mut scan, started_inst);
    Ok(scan)
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IncrementalUpdateStats {
    pub files_reparsed: usize,
    pub cache_hits: usize,
    pub files_dropped: usize,
}

#[cfg(test)]
#[derive(Debug, Clone)]
pub(crate) struct IncrementalScanResult {
    pub scan: WorkspaceScan,
    pub stats: IncrementalUpdateStats,
}

#[derive(Debug, Clone)]
pub(crate) struct AstScanCache {
    #[cfg(test)]
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
    #[cfg(test)]
    pub mtime_ms: u64,
    #[cfg(test)]
    pub len: u64,
    #[cfg(test)]
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
    /// Same counts, but excluding anything inside a `#[cfg(test)]` scope.
    /// The difference between the two is what makes "referenced only by tests"
    /// sayable — a category invisible to every reference-counting tier.
    ident_refs_nontest: HashMap<String, usize>,
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

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileSignature {
    mtime_ms: u64,
    len: u64,
}

impl AstScanCache {
    pub(crate) fn from_root(root: &Path) -> Result<Self, ScanError> {
        let workspace = discover_workspace(root)?;
        crate::repo_scan_policy::charge_generated_work(
            workspace.crate_dirs.len(),
            workspace.crate_dirs.keys().map(String::len).sum(),
            "AST known-crate index",
        )?;
        let known_crate_names: BTreeSet<String> = workspace.crate_dirs.keys().cloned().collect();
        let mut files = BTreeMap::new();
        for (cname, crate_files) in &workspace.files_by_crate {
            crate::repo_scan_policy::check_deadline()?;
            let Some(crate_root) = workspace.crate_dirs.get(cname) else {
                continue;
            };
            for abs in crate_files {
                crate::repo_scan_policy::check_deadline()?;
                let cached = parse_file_ast(root, cname, crate_root, abs, &known_crate_names)?;
                crate::repo_scan_policy::charge_generated_work(
                    1,
                    cached.rel_path.len(),
                    "AST parsed-file cache index",
                )?;
                files.insert(cached.rel_path.clone(), cached);
            }
        }
        crate::repo_scan_policy::charge_generated_work(
            workspace.files_by_crate.len(),
            workspace.files_by_crate.keys().map(String::len).sum(),
            "AST crate-order index",
        )?;
        Ok(Self {
            #[cfg(test)]
            root_path: root.to_path_buf(),
            crate_dirs: workspace.crate_dirs,
            crate_internal_deps: workspace.crate_internal_deps,
            crate_order: workspace.files_by_crate.keys().cloned().collect(),
            files,
        })
    }
}

pub(crate) fn assemble_scan(root: &Path, cache: &AstScanCache) -> Result<WorkspaceScan, ScanError> {
    let started_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    assemble_scan_at(root, cache, started_ms)
}

#[cfg(test)]
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
    let mut scan = assemble_scan(root, cache)?;
    reset_scan_start(&mut scan, started_ms);
    finish_scan_timing(&mut scan, started_inst);
    Ok(IncrementalScanResult { scan, stats })
}

fn reset_scan_start(scan: &mut WorkspaceScan, started_ms: u64) {
    scan.scan_id = format!("ws_{started_ms}_{}", uuid::Uuid::new_v4().simple());
    scan.started_at_unix_ms = started_ms;
}

fn finish_scan_timing(scan: &mut WorkspaceScan, started_inst: std::time::Instant) {
    let elapsed_ms = started_inst.elapsed().as_millis() as u64;
    scan.finished_at_unix_ms = scan.started_at_unix_ms + elapsed_ms;
    scan.duration_ms = elapsed_ms;
}

fn assemble_scan_at(root: &Path, cache: &AstScanCache, started_ms: u64) -> Result<WorkspaceScan, ScanError> {
    let mut scan = WorkspaceScan {
        scan_id: format!("ws_{started_ms}_{}", uuid::Uuid::new_v4().simple()),
        root_path: root.display().to_string(),
        started_at_unix_ms: started_ms,
        diagnostics: ScanDiagnostics::default(),
        ..Default::default()
    };
    let mut index = Index::default();
    let mut file_idx_by_path: HashMap<String, usize> = HashMap::new();
    let mut local_symbol_to_global: HashMap<(String, usize), usize> = HashMap::new();
    let mut ident_refs: HashMap<String, usize> = HashMap::new();
    let mut ident_refs_nontest: HashMap<String, usize> = HashMap::new();

    for cname in &cache.crate_order {
        crate::repo_scan_policy::check_deadline()?;
        let Some(crate_root) = cache.crate_dirs.get(cname) else {
            continue;
        };
        let mut crate_loc = 0usize;
        let mut crate_file_count = 0usize;
        for file in cache.files.values().filter(|f| &f.crate_name == cname) {
            crate::repo_scan_policy::check_deadline()?;
            let file_idx = scan.files.len();
            crate::repo_scan_policy::charge_generated_work(
                2,
                file.rel_path
                    .len()
                    .saturating_mul(2)
                    .saturating_add(file.crate_name.len())
                    .saturating_add(file.module_path.len())
                    .saturating_add(file.doc_full.as_deref().map_or(0, str::len)),
                "scan output",
            )?;
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
            crate::repo_scan_policy::charge_generated_work(
                file.stubs.len(),
                file.stubs
                    .iter()
                    .map(|stub| {
                        stub.crate_name
                            .len()
                            .saturating_add(stub.file_rel_path.len())
                            .saturating_add(stub.kind.len())
                            .saturating_add(stub.snippet.len())
                    })
                    .sum(),
                "AST stub output clone",
            )?;
            scan.stubs.extend(file.stubs.iter().cloned());
            crate::repo_scan_policy::charge_generated_work(
                file.deps.len(),
                file.deps
                    .iter()
                    .map(|dep| {
                        dep.from_crate
                            .len()
                            .saturating_add(dep.from_file.len())
                            .saturating_add(dep.to_module.len())
                            .saturating_add(dep.raw.len())
                    })
                    .sum(),
                "AST dependency output clone",
            )?;
            scan.deps.extend(file.deps.iter().cloned());
            for (local_idx, symbol) in file.symbols.iter().cloned().enumerate() {
                if local_idx % 256 == 0 {
                    crate::repo_scan_policy::check_deadline()?;
                }
                let global_idx = scan.symbols.len();
                crate::repo_scan_policy::charge_generated_work(
                    2,
                    symbol
                        .crate_name
                        .len()
                        .saturating_add(symbol.module_path.len())
                        .saturating_add(symbol.file_rel_path.len().saturating_mul(2))
                        .saturating_add(symbol.kind.len())
                        .saturating_add(symbol.name.len()),
                    "AST symbol output and local index",
                )?;
                scan.symbols.push(symbol);
                local_symbol_to_global.insert((file.rel_path.clone(), local_idx), global_idx);
            }
            for (ident, count) in &file.ident_refs {
                match ident_refs.entry(ident.clone()) {
                    std::collections::hash_map::Entry::Occupied(mut entry) => {
                        *entry.get_mut() = entry.get().saturating_add(*count);
                    }
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        crate::repo_scan_policy::charge_generated_work(
                            1,
                            ident.len(),
                            "assembled AST identifier index",
                        )?;
                        entry.insert(*count);
                    }
                }
            }
            for (ident, count) in &file.ident_refs_nontest {
                match ident_refs_nontest.entry(ident.clone()) {
                    std::collections::hash_map::Entry::Occupied(mut entry) => {
                        *entry.get_mut() = entry.get().saturating_add(*count);
                    }
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        crate::repo_scan_policy::charge_generated_work(
                            1,
                            ident.len(),
                            "assembled non-test AST identifier index",
                        )?;
                        entry.insert(*count);
                    }
                }
            }
        }
        let rel_path = crate_root
            .strip_prefix(root)
            .map_or_else(|_| crate_root.display().to_string(), |p| p.display().to_string());
        let internal_deps = cache.crate_internal_deps.get(cname).cloned().unwrap_or_default();
        crate::repo_scan_policy::charge_generated_work(
            1,
            cname
                .len()
                .saturating_add(rel_path.len())
                .saturating_add(internal_deps.iter().map(String::len).sum::<usize>()),
            "AST crate output",
        )?;
        scan.crates.push(CrateInfo {
            name: cname.clone(),
            rel_path,
            internal_deps,
            file_count: crate_file_count,
            total_loc: crate_loc,
        });
    }

    for file in cache.files.values() {
        crate::repo_scan_policy::check_deadline()?;
        for (def_index, def) in file.fns.iter().enumerate() {
            if def_index % 256 == 0 {
                crate::repo_scan_policy::check_deadline()?;
            }
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
            })?;
        }
    }

    denormalize_defines(&mut scan, &file_idx_by_path)?;
    resolve_routes_from_cache(cache, &index, &mut scan)?;
    resolve_references(&mut scan, &index, &file_idx_by_path)?;
    build_referenced_by(&mut scan)?;
    compute_dead_code(&mut scan, &ident_refs)?;
    compute_test_only(&mut scan, &ident_refs, &ident_refs_nontest)?;
    crate::workspace_scan_manifests::attach_external_deps_if_enabled(root, &mut scan)?;
    roll_up_stats(&mut scan)?;
    Ok(scan)
}

#[cfg(test)]
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
        crate::repo_scan_policy::check_deadline()?;
        let Some(crate_root) = workspace.crate_dirs.get(cname) else {
            continue;
        };
        for abs in files {
            crate::repo_scan_policy::check_deadline()?;
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
                        let src = crate::workspace_scan::read_scan_bytes(abs)?;
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
    let mut discovery_error = None;
    walk_dir(root, root, &mut |rel_path, abs_path| {
        if discovery_error.is_some() {
            return;
        }
        if abs_path.file_name().and_then(|n| n.to_str()) == Some("Cargo.toml") && rel_path != Path::new("Cargo.toml") {
            match crate::repo_scan_policy::charge_generated_work(
                1,
                abs_path.as_os_str().len(),
                "AST Cargo manifest discovery index",
            ) {
                Ok(()) => cargo_files.push(abs_path.to_path_buf()),
                Err(error) => discovery_error = Some(error),
            }
        }
    })?;
    if let Some(error) = discovery_error {
        return Err(error);
    }
    cargo_files.sort();

    let mut out = WorkspaceFiles::default();
    for cargo in &cargo_files {
        crate::repo_scan_policy::check_deadline()?;
        let crate_dir = cargo.parent().unwrap_or(root).to_path_buf();
        let toml = crate::workspace_scan::read_scan_to_string(cargo)?;
        let name = parse_crate_name(&toml).unwrap_or_else(|| {
            crate_dir
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("?")
                .to_string()
        });
        let internal_deps = parse_internal_path_deps(&toml)?;
        crate::repo_scan_policy::charge_generated_work(
            2,
            name.len().saturating_mul(2).saturating_add(crate_dir.as_os_str().len()),
            "AST crate manifest indexes",
        )?;
        out.crate_internal_deps.insert(name.clone(), internal_deps);
        out.crate_dirs.insert(name, crate_dir);
    }

    for (name, dir) in &out.crate_dirs {
        crate::repo_scan_policy::check_deadline()?;
        let src = dir.join("src");
        if !crate::repo_scan_policy::scan_path_is_directory(&src)? {
            continue;
        }
        let mut files = Vec::new();
        let mut discovery_error = None;
        walk_dir(&src, &src, &mut |_rel, abs| {
            if discovery_error.is_some() {
                return;
            }
            if abs.extension().and_then(|e| e.to_str()) == Some("rs") {
                match crate::repo_scan_policy::charge_generated_work(
                    1,
                    abs.as_os_str().len(),
                    "AST Rust source discovery index",
                ) {
                    Ok(()) => files.push(abs.to_path_buf()),
                    Err(error) => discovery_error = Some(error),
                }
            }
        })?;
        if let Some(error) = discovery_error {
            return Err(error);
        }
        files.sort();
        crate::repo_scan_policy::charge_generated_work(1, name.len(), "AST crate source index")?;
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
    fn push(&mut self, def: FnDef) -> Result<(), ScanError> {
        let idx = self.defs.len();
        crate::repo_scan_policy::charge_generated_work(
            2usize.saturating_add(def.calls.len()),
            def.simple
                .len()
                .saturating_add(def.qualified.len())
                .saturating_add(def.crate_name.len())
                .saturating_add(def.module_path.len())
                .saturating_add(def.file.len())
                .saturating_add(
                    def.calls
                        .iter()
                        .flat_map(|call| call.segs.iter())
                        .map(String::len)
                        .sum::<usize>(),
                ),
            "AST function indexes",
        )?;
        self.by_simple.entry(def.simple.clone()).or_default().push(idx);
        self.by_qualified.insert(def.qualified.clone(), idx);
        let parts: Vec<&str> = def.qualified.split("::").collect();
        for start in 0..parts.len().saturating_sub(1) {
            let suffix = parts[start..].join("::");
            crate::repo_scan_policy::charge_generated_work(1, suffix.len(), "AST function suffix index")?;
            self.by_suffix.entry(suffix).or_default().push(idx);
        }
        self.defs.push(def);
        Ok(())
    }

    fn resolve(&self, call: &CallRef, from: &FnDef) -> Result<Option<usize>, ScanError> {
        if call.kind == CallKind::Method {
            return Ok(self.resolve_method(call));
        }
        if call.kind != CallKind::Func {
            return Ok(None);
        }
        let segs = normalize_call_segs(&call.segs, from);
        crate::repo_scan_policy::charge_generated_work(
            segs.len(),
            segs.iter().map(String::len).sum(),
            "normalized AST call path",
        )?;
        if segs.is_empty() {
            return Ok(None);
        }
        if segs.len() >= 2 {
            let suffix = segs.join("::");
            return Ok(match self.by_suffix.get(&suffix).map(Vec::as_slice) {
                Some([one]) => Some(*one),
                _ => None,
            });
        }

        let simple = segs[0].clone();
        let Some(candidates) = self.by_simple.get(&simple) else {
            return Ok(None);
        };
        let current_module = format!("{}::{}", from.module_path, simple);
        if let Some(one) = unique_candidate(candidates, |idx| self.defs[idx].qualified == current_module)? {
            return Ok(Some(one));
        }

        if let Some(one) = unique_candidate(candidates, |idx| self.defs[idx].file == from.file)? {
            return Ok(Some(one));
        }

        if let Some(one) = unique_candidate(candidates, |idx| self.defs[idx].crate_name == from.crate_name)? {
            return Ok(Some(one));
        }

        Ok(match candidates.as_slice() {
            [one] => Some(*one),
            _ => None,
        })
    }

    /// Resolve `x.method()` — but only when the name is unambiguous.
    ///
    /// A method call carries no receiver type, so the only honest resolution is
    /// by name. Guessing between candidates would manufacture edges that look
    /// like evidence, so this resolves **only when exactly one definition in the
    /// whole workspace bears the name**. `.new()`, `.len()` and `.push()` are
    /// therefore skipped, and `replay_available` or `resource_metadata_url`
    /// resolve.
    ///
    /// The failure mode is deliberately asymmetric: this can miss an edge, and
    /// cannot invent one between two workspace symbols. That matters because the
    /// answer a missing edge produces — an empty blast radius — reads as
    /// "nothing breaks".
    fn resolve_method(&self, call: &CallRef) -> Option<usize> {
        let [name] = call.segs.as_slice() else {
            return None;
        };
        match self.by_simple.get(name).map(Vec::as_slice) {
            Some([one]) => Some(*one),
            _ => None,
        }
    }
}

fn unique_candidate(candidates: &[usize], predicate: impl Fn(usize) -> bool) -> Result<Option<usize>, ScanError> {
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

struct CallCollector {
    calls: Vec<CallRef>,
    depth: usize,
    depth_exceeded: bool,
}

impl<'ast> Visit<'ast> for CallCollector {
    fn visit_expr(&mut self, expr: &'ast syn::Expr) {
        if self.depth >= crate::workspace_scan::RUST_SYNTAX_MAX_DEPTH {
            self.depth_exceeded = true;
            return;
        }
        self.depth += 1;
        syn::visit::visit_expr(self, expr);
        self.depth -= 1;
    }

    fn visit_expr_call(&mut self, c: &'ast syn::ExprCall) {
        if crate::repo_scan_policy::check_deadline().is_err() {
            return;
        }
        if let syn::Expr::Path(p) = &*c.func {
            let segs: Vec<String> = p.path.segments.iter().map(|s| s.ident.to_string()).collect();
            if !segs.is_empty() {
                let bytes = segs.iter().map(String::len).sum();
                if crate::repo_scan_policy::charge_generated_work(1, bytes, "AST call candidate").is_ok() {
                    self.calls.push(CallRef {
                        segs,
                        kind: CallKind::Func,
                    });
                }
            }
        }
        syn::visit::visit_expr_call(self, c);
    }

    fn visit_expr_method_call(&mut self, m: &'ast syn::ExprMethodCall) {
        if crate::repo_scan_policy::check_deadline().is_err() {
            return;
        }
        let method = m.method.to_string();
        if crate::repo_scan_policy::charge_generated_work(1, method.len(), "AST call candidate").is_ok() {
            self.calls.push(CallRef {
                segs: vec![method],
                kind: CallKind::Method,
            });
        }
        syn::visit::visit_expr_method_call(self, m);
    }

    fn visit_macro(&mut self, m: &'ast syn::Macro) {
        if crate::repo_scan_policy::check_deadline().is_err() {
            return;
        }
        if let Some(seg) = m.path.segments.last() {
            let ident = seg.ident.to_string();
            if crate::repo_scan_policy::charge_generated_work(1, ident.len(), "AST call candidate").is_ok() {
                self.calls.push(CallRef {
                    segs: vec![ident],
                    kind: CallKind::Macro,
                });
            }
        }
        // A macro body is an opaque token stream to `syn::visit`, so every call
        // inside one used to be invisible to the reference graph. In a daemon
        // that is not an edge case: a `tokio::select!` arm can hold most of a
        // subsystem. `select_witness_signer` had ZERO recorded callers for
        // exactly this reason, despite being called from `main`.
        //
        // Tokens cannot be type-checked, so this is lexical: it recovers the
        // call *shapes* and leaves resolution to the same index every other
        // call goes through.
        collect_calls_in_tokens(m.tokens.clone(), &mut self.calls);
        syn::visit::visit_macro(self, m);
    }
}

/// Recover `path::to::fn(..)` and `.method(..)` call shapes from a raw token
/// stream.
///
/// Lexical by necessity — macro bodies are not required to be valid Rust
/// expressions (`tokio::select!` arms certainly are not), so parsing is not an
/// option. The shapes recognised are:
///
///   * `ident (` — a plain call,
///   * `a :: b :: c (` — a path call, emitted with its full segment list,
///   * `. ident (` — a method call.
///
/// Over-collection is the safe direction here: an unresolvable name simply
/// finds nothing in the index and disappears. Under-collection is what produced
/// an empty blast radius for a symbol with a live caller.
fn collect_calls_in_tokens(stream: proc_macro2::TokenStream, out: &mut Vec<CallRef>) {
    if crate::repo_scan_policy::check_deadline().is_err() {
        return;
    }
    let mut tokens = Vec::new();
    for token in stream {
        if crate::repo_scan_policy::charge_generated_work(
            1,
            std::mem::size_of::<proc_macro2::TokenTree>(),
            "macro token work queue",
        )
        .is_err()
        {
            return;
        }
        tokens.push(token);
    }
    let mut i = 0usize;
    while i < tokens.len() {
        if crate::repo_scan_policy::check_deadline().is_err() {
            return;
        }
        match &tokens[i] {
            proc_macro2::TokenTree::Group(g) => {
                collect_calls_in_tokens(g.stream(), out);
                i += 1;
            }
            proc_macro2::TokenTree::Ident(ident) => {
                // Walk back over any `::`-joined prefix so `crate::a::b(..)` is
                // emitted whole rather than as its last segment.
                let mut segs = vec![ident.to_string()];
                let mut j = i;
                // `… prev :: ident` — step back three tokens at a time.
                while j >= 3 && is_path_sep(&tokens[j - 2..j]) {
                    let proc_macro2::TokenTree::Ident(prev) = &tokens[j - 3] else {
                        break;
                    };
                    segs.insert(0, prev.to_string());
                    j -= 3;
                }
                let followed_by_call = matches!(
                    tokens.get(i + 1),
                    Some(proc_macro2::TokenTree::Group(g)) if g.delimiter() == proc_macro2::Delimiter::Parenthesis
                );
                if followed_by_call {
                    let is_method =
                        i >= 1 && matches!(&tokens[i - 1], proc_macro2::TokenTree::Punct(p) if p.as_char() == '.');
                    let segs = if is_method { vec![ident.to_string()] } else { segs };
                    let bytes = segs.iter().map(String::len).sum();
                    if crate::repo_scan_policy::charge_generated_work(1, bytes, "macro call candidate").is_err() {
                        return;
                    }
                    out.push(CallRef {
                        kind: if is_method { CallKind::Method } else { CallKind::Func },
                        segs,
                    });
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
}

/// True when the two tokens are a `::` separator.
fn is_path_sep(pair: &[proc_macro2::TokenTree]) -> bool {
    matches!(
        (&pair[0], &pair[1]),
        (proc_macro2::TokenTree::Punct(a), proc_macro2::TokenTree::Punct(b))
            if a.as_char() == ':' && b.as_char() == ':'
    )
}

fn collect_calls(block: &syn::Block) -> Result<Vec<CallRef>, ScanError> {
    let mut collector = CallCollector {
        calls: Vec::new(),
        depth: 0,
        depth_exceeded: false,
    };
    collector.visit_block(block);
    if collector.depth_exceeded {
        return Err(ScanError::Policy(format!(
            "Rust AST nesting exceeds {}",
            crate::workspace_scan::RUST_SYNTAX_MAX_DEPTH
        )));
    }
    crate::repo_scan_policy::check_deadline()?;
    Ok(collector.calls)
}

#[derive(Default)]
struct IdentRefCollector {
    counts: HashMap<String, usize>,
    /// When set, `#[cfg(test)]` items are not descended into.
    skip_test_scopes: bool,
    depth: usize,
    depth_exceeded: bool,
}

impl<'ast> Visit<'ast> for IdentRefCollector {
    fn visit_expr(&mut self, expr: &'ast syn::Expr) {
        if self.depth >= crate::workspace_scan::RUST_SYNTAX_MAX_DEPTH {
            self.depth_exceeded = true;
            return;
        }
        self.depth += 1;
        syn::visit::visit_expr(self, expr);
        self.depth -= 1;
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        if crate::repo_scan_policy::check_deadline().is_err() {
            return;
        }
        for seg in &path.segments {
            self.bump(seg.ident.to_string());
        }
        syn::visit::visit_path(self, path);
    }

    fn visit_expr_method_call(&mut self, m: &'ast syn::ExprMethodCall) {
        if crate::repo_scan_policy::check_deadline().is_err() {
            return;
        }
        self.bump(m.method.to_string());
        syn::visit::visit_expr_method_call(self, m);
    }

    fn visit_macro(&mut self, m: &'ast syn::Macro) {
        if crate::repo_scan_policy::check_deadline().is_err() {
            return;
        }
        for seg in &m.path.segments {
            self.bump(seg.ident.to_string());
        }
        // The macro's *body* counts too. Without this, a symbol used only from
        // inside a `tokio::select!` arm, a `json!` literal or an `assert!` reads
        // as unreferenced and is reported dead — the single largest source of
        // false positives in this tier, and the one that produced
        // `dead_candidate__static_and_runtime_agree` for live symbols.
        self.bump_tokens(m.tokens.clone());
        syn::visit::visit_macro(self, m);
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        if crate::repo_scan_policy::check_deadline().is_err() {
            return;
        }
        self.visit_use_tree_idents(&item.tree);
        syn::visit::visit_item_use(self, item);
    }

    fn visit_item(&mut self, item: &'ast syn::Item) {
        if crate::repo_scan_policy::check_deadline().is_err() {
            return;
        }
        if self.skip_test_scopes && item_is_cfg_test(item) {
            return;
        }
        if self.depth >= crate::workspace_scan::RUST_SYNTAX_MAX_DEPTH {
            self.depth_exceeded = true;
            return;
        }
        self.depth += 1;
        syn::visit::visit_item(self, item);
        self.depth -= 1;
    }
}

/// True when an item carries `#[cfg(test)]`.
///
/// Matched on the attribute's tokens rather than by parsing the full `cfg`
/// grammar: `cfg(test)` and `cfg(all(test, …))` both mention `test` at the top
/// level, and anything cleverer would be guessing. Over-matching here would
/// hide a real reference, so the check stays literal.
fn item_is_cfg_test(item: &syn::Item) -> bool {
    let attrs: &[syn::Attribute] = match item {
        syn::Item::Mod(m) => &m.attrs,
        syn::Item::Fn(f) => &f.attrs,
        syn::Item::Impl(i) => &i.attrs,
        syn::Item::Struct(s) => &s.attrs,
        syn::Item::Enum(e) => &e.attrs,
        _ => return false,
    };
    attrs.iter().any(|a| match &a.meta {
        // `cfg(test)`, `cfg(all(test, …))`, `cfg(any(test, …))` all mention
        // `test` as a bare token inside the list.
        syn::Meta::List(list) if a.path().is_ident("cfg") => {
            list.tokens
                .clone()
                .into_iter()
                .any(|t| matches!(t, proc_macro2::TokenTree::Ident(ref i) if i == "test"))
                || list.tokens.to_string().replace(' ', "").contains("(test")
        }
        _ => false,
    })
}

impl IdentRefCollector {
    fn bump(&mut self, ident: String) {
        match self.counts.entry(ident) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                *entry.get_mut() = entry.get().saturating_add(1);
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                if crate::repo_scan_policy::charge_generated_work(
                    1,
                    entry.key().len(),
                    "AST identifier reference index",
                )
                .is_ok()
                {
                    entry.insert(1);
                }
            }
        }
    }

    /// Count every identifier in a macro's token stream, recursing into groups.
    ///
    /// Deliberately indiscriminate: this tier asks "is this name mentioned
    /// anywhere at all", and for that question a false *mention* only ever
    /// withholds a dead-code flag, whereas a missed mention reports live code as
    /// dead. Those costs are not symmetric.
    fn bump_tokens(&mut self, stream: proc_macro2::TokenStream) {
        for tt in stream {
            if crate::repo_scan_policy::check_deadline().is_err() {
                return;
            }
            match tt {
                proc_macro2::TokenTree::Ident(ident) => self.bump(ident.to_string()),
                proc_macro2::TokenTree::Group(g) => self.bump_tokens(g.stream()),
                _ => {}
            }
        }
    }

    fn visit_use_tree_idents(&mut self, tree: &syn::UseTree) {
        if crate::repo_scan_policy::check_deadline().is_err() {
            return;
        }
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

fn collect_identifier_refs(file: &syn::File, into: &mut HashMap<String, usize>) -> Result<(), ScanError> {
    let mut collector = IdentRefCollector::default();
    collector.visit_file(file);
    if collector.depth_exceeded {
        return Err(ScanError::Policy(format!(
            "Rust AST nesting exceeds {}",
            crate::workspace_scan::RUST_SYNTAX_MAX_DEPTH
        )));
    }
    crate::repo_scan_policy::check_deadline()?;
    for (ident, count) in collector.counts {
        match into.entry(ident) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                *entry.get_mut() = entry.get().saturating_add(count);
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                crate::repo_scan_policy::charge_generated_work(
                    1,
                    entry.key().len(),
                    "merged AST identifier reference index",
                )?;
                entry.insert(count);
            }
        }
    }
    Ok(())
}

/// As [`collect_identifier_refs`], but blind to everything under `#[cfg(test)]`.
fn collect_identifier_refs_nontest(file: &syn::File, into: &mut HashMap<String, usize>) -> Result<(), ScanError> {
    let mut collector = IdentRefCollector {
        skip_test_scopes: true,
        ..IdentRefCollector::default()
    };
    collector.visit_file(file);
    if collector.depth_exceeded {
        return Err(ScanError::Policy(format!(
            "Rust AST nesting exceeds {}",
            crate::workspace_scan::RUST_SYNTAX_MAX_DEPTH
        )));
    }
    crate::repo_scan_policy::check_deadline()?;
    for (ident, count) in collector.counts {
        match into.entry(ident) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                *entry.get_mut() = entry.get().saturating_add(count);
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                crate::repo_scan_policy::charge_generated_work(
                    1,
                    entry.key().len(),
                    "merged non-test AST identifier reference index",
                )?;
                entry.insert(count);
            }
        }
    }
    Ok(())
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
    let src = crate::workspace_scan::read_scan_to_string(abs)?;
    #[cfg(test)]
    let signature = file_signature(abs)?;
    let loc = src.lines().count();
    #[cfg(test)]
    let content_hash = blake3::hash(src.as_bytes()).to_hex().to_string();
    let (doc_full, doc_summary) = parse_file_doc_header(&src);
    let is_test_file = crate::workspace_scan::looks_like_test_file(&rel_str, &src);
    crate::repo_scan_policy::charge_generated_work(
        1,
        rel_str
            .len()
            .saturating_add(crate_name.len())
            .saturating_add(module_path.len())
            .saturating_add(doc_full.as_deref().map_or(0, str::len)),
        "AST file cache",
    )?;
    let mut stubs = Vec::new();
    let is_scanner_source = rel_str.ends_with("corecruxd/src/workspace_scan.rs")
        || rel_str.ends_with("corecruxd/src/workspace_scan_ast.rs");
    if !is_scanner_source {
        for (line_no, line) in src.lines().enumerate() {
            if line_no % 256 == 0 {
                crate::repo_scan_policy::check_deadline()?;
            }
            if let Some((kind, snippet)) = parse_stub_line(line) {
                crate::repo_scan_policy::charge_generated_work(
                    1,
                    crate_name
                        .len()
                        .saturating_add(rel_str.len())
                        .saturating_add(kind.len())
                        .saturating_add(snippet.len()),
                    "scan output",
                )?;
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
    crate::repo_scan_policy::check_deadline()?;
    crate::workspace_scan::validate_rust_syntax_complexity(&src)?;
    crate::repo_scan_policy::charge_source_parse_work(&src, "Rust AST parser work")?;
    if let Ok(parsed) = syn::parse_file(&src) {
        crate::repo_scan_policy::check_deadline()?;
        let mut ident_refs = HashMap::new();
        collect_identifier_refs(&parsed, &mut ident_refs)?;
        // Second pass with test scopes elided. A file that *is* a test file
        // contributes nothing here: every reference in it is a test reference.
        let mut ident_refs_nontest = HashMap::new();
        if !is_test_file {
            collect_identifier_refs_nontest(&parsed, &mut ident_refs_nontest)?;
        }
        let mut line_lookup = LineLookup::new(&src)?;
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
            0,
        )?;
        Ok(CachedFile {
            rel_path: rel_str.clone(),
            crate_name: crate_name.to_string(),
            module_path,
            #[cfg(test)]
            mtime_ms: signature.mtime_ms,
            #[cfg(test)]
            len: signature.len,
            #[cfg(test)]
            content_hash,
            loc,
            doc_summary,
            doc_full,
            is_test_file,
            stubs,
            symbols: parts.symbols,
            fns: parts.fns,
            deps: parts.deps,
            routes: parse_routes_in_source(&src, &rel_str)?,
            ident_refs,
            ident_refs_nontest,
        })
    } else {
        Ok(CachedFile {
            rel_path: rel_str.clone(),
            crate_name: crate_name.to_string(),
            module_path,
            #[cfg(test)]
            mtime_ms: signature.mtime_ms,
            #[cfg(test)]
            len: signature.len,
            #[cfg(test)]
            content_hash,
            loc,
            doc_summary,
            doc_full,
            is_test_file,
            stubs,
            symbols: Vec::new(),
            fns: Vec::new(),
            deps: Vec::new(),
            routes: parse_routes_in_source(&src, &rel_str)?,
            ident_refs: HashMap::new(),
            ident_refs_nontest: HashMap::new(),
        })
    }
}

fn index_items(
    parts: &mut ParsedFileParts,
    known_crates: &BTreeSet<String>,
    line_lookup: &mut LineLookup,
    items: &[syn::Item],
    ctx: FileCtx<'_>,
    depth: usize,
) -> Result<(), ScanError> {
    if depth > crate::workspace_scan::RUST_SYNTAX_MAX_DEPTH {
        return Err(ScanError::Policy(format!(
            "Rust inline-module nesting exceeds {}",
            crate::workspace_scan::RUST_SYNTAX_MAX_DEPTH
        )));
    }
    for item in items {
        crate::repo_scan_policy::check_deadline()?;
        match item {
            syn::Item::Fn(f) => {
                let name = f.sig.ident.to_string();
                let local_symbol_idx = push_symbol(parts, ctx, line_lookup, "fn", &name, is_pub(&f.vis))?;
                let qualified = qualify(ctx.module_path, &name);
                let calls = collect_calls(&f.block)?;
                crate::repo_scan_policy::charge_generated_work(
                    1,
                    qualified
                        .len()
                        .saturating_add(name.len())
                        .saturating_add(ctx.crate_name.len())
                        .saturating_add(ctx.module_path.len())
                        .saturating_add(ctx.rel_path.len()),
                    "AST function cache",
                )?;
                parts.fns.push(CachedFnDef {
                    qualified,
                    simple: name,
                    crate_name: ctx.crate_name.to_string(),
                    module_path: ctx.module_path.to_string(),
                    file: ctx.rel_path.to_string(),
                    local_symbol_idx,
                    calls,
                });
            }
            syn::Item::Struct(s) => {
                let name = s.ident.to_string();
                let _ = push_symbol(parts, ctx, line_lookup, "struct", &name, is_pub(&s.vis))?;
            }
            syn::Item::Enum(e) => {
                let name = e.ident.to_string();
                let _ = push_symbol(parts, ctx, line_lookup, "enum", &name, is_pub(&e.vis))?;
            }
            syn::Item::Trait(t) => {
                let name = t.ident.to_string();
                let _ = push_symbol(parts, ctx, line_lookup, "trait", &name, is_pub(&t.vis))?;
            }
            syn::Item::Type(t) => {
                let name = t.ident.to_string();
                let _ = push_symbol(parts, ctx, line_lookup, "type", &name, is_pub(&t.vis))?;
            }
            syn::Item::Const(c) => {
                let name = c.ident.to_string();
                let _ = push_symbol(parts, ctx, line_lookup, "const", &name, is_pub(&c.vis))?;
            }
            syn::Item::Static(s) => {
                let name = s.ident.to_string();
                let _ = push_symbol(parts, ctx, line_lookup, "static", &name, is_pub(&s.vis))?;
            }
            syn::Item::Mod(m) => {
                let name = m.ident.to_string();
                let _ = push_symbol(parts, ctx, line_lookup, "mod", &name, is_pub(&m.vis))?;
                if let Some((_, inner)) = &m.content {
                    let nested = qualify(ctx.module_path, &name);
                    let nested_ctx = FileCtx {
                        module_path: &nested,
                        ..ctx
                    };
                    index_items(
                        parts,
                        known_crates,
                        line_lookup,
                        inner,
                        nested_ctx,
                        depth.saturating_add(1),
                    )?;
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
                        let local_symbol_idx = push_symbol(parts, ctx, line_lookup, "fn", &name, is_pub(&f.vis))?;
                        let qualified = qualify(&impl_base, &name);
                        let calls = collect_calls(&f.block)?;
                        crate::repo_scan_policy::charge_generated_work(
                            1,
                            qualified
                                .len()
                                .saturating_add(name.len())
                                .saturating_add(ctx.crate_name.len())
                                .saturating_add(ctx.module_path.len())
                                .saturating_add(ctx.rel_path.len()),
                            "AST function cache",
                        )?;
                        parts.fns.push(CachedFnDef {
                            qualified,
                            simple: name,
                            crate_name: ctx.crate_name.to_string(),
                            module_path: ctx.module_path.to_string(),
                            file: ctx.rel_path.to_string(),
                            local_symbol_idx,
                            calls,
                        });
                    }
                }
            }
            syn::Item::Use(u) => {
                for raw in use_tree_paths(&u.tree)? {
                    if let Some(to_module) = use_path_to_module(&raw, ctx.crate_name, known_crates) {
                        crate::repo_scan_policy::charge_generated_work(
                            1,
                            ctx.crate_name
                                .len()
                                .saturating_add(ctx.rel_path.len())
                                .saturating_add(to_module.len())
                                .saturating_add(raw.len()),
                            "scan output",
                        )?;
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
    Ok(())
}

fn push_symbol(
    parts: &mut ParsedFileParts,
    ctx: FileCtx<'_>,
    line_lookup: &mut LineLookup,
    kind: &str,
    name: &str,
    is_pub: bool,
) -> Result<usize, ScanError> {
    crate::repo_scan_policy::charge_generated_work(
        1,
        ctx.crate_name
            .len()
            .saturating_add(ctx.module_path.len())
            .saturating_add(ctx.rel_path.len())
            .saturating_add(kind.len())
            .saturating_add(name.len()),
        "scan output",
    )?;
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
    Ok(symbol_idx)
}

struct LineLookup {
    by_kind_name: HashMap<(String, String), VecDeque<usize>>,
}

impl LineLookup {
    fn new(src: &str) -> Result<Self, ScanError> {
        let mut by_kind_name: HashMap<(String, String), VecDeque<usize>> = HashMap::new();
        for (idx, line) in src.lines().enumerate() {
            if let Some((kind, name)) = parse_decl_line(line) {
                crate::repo_scan_policy::charge_generated_work(
                    1,
                    kind.len().saturating_add(name.len()),
                    "AST declaration line index",
                )?;
                by_kind_name
                    .entry((kind.to_string(), name))
                    .or_default()
                    .push_back(idx + 1);
            }
        }
        Ok(Self { by_kind_name })
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

fn use_tree_paths(tree: &syn::UseTree) -> Result<Vec<String>, ScanError> {
    fn walk(prefix: &mut Vec<String>, tree: &syn::UseTree, out: &mut Vec<String>) -> Result<(), ScanError> {
        match tree {
            syn::UseTree::Path(p) => {
                prefix.push(p.ident.to_string());
                walk(prefix, &p.tree, out)?;
                prefix.pop();
            }
            syn::UseTree::Name(n) => {
                let mut parts = prefix.clone();
                parts.push(n.ident.to_string());
                let path = parts.join("::");
                crate::repo_scan_policy::charge_generated_work(1, path.len(), "AST use-tree path")?;
                out.push(path);
            }
            syn::UseTree::Rename(r) => {
                let mut parts = prefix.clone();
                parts.push(r.ident.to_string());
                let path = parts.join("::");
                crate::repo_scan_policy::charge_generated_work(1, path.len(), "AST use-tree path")?;
                out.push(path);
            }
            syn::UseTree::Glob(_) => {
                let mut parts = prefix.clone();
                parts.push("*".to_string());
                let path = parts.join("::");
                crate::repo_scan_policy::charge_generated_work(1, path.len(), "AST use-tree path")?;
                out.push(path);
            }
            syn::UseTree::Group(g) => {
                for item in &g.items {
                    walk(prefix, item, out)?;
                }
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    walk(&mut Vec::new(), tree, &mut out)?;
    Ok(out)
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

#[cfg(test)]
fn absolutize(root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

#[cfg(test)]
fn file_signature(path: &Path) -> Result<FileSignature, ScanError> {
    let metadata = std::fs::symlink_metadata(path)?;
    crate::repo_scan_policy::discover_file(path, &metadata)?;
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

#[cfg(test)]
fn is_rs_path(path: &Path) -> bool {
    path.extension().and_then(|e| e.to_str()) == Some("rs")
}

#[cfg(test)]
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

fn denormalize_defines(scan: &mut WorkspaceScan, file_idx_by_path: &HashMap<String, usize>) -> Result<(), ScanError> {
    let mut define_names_by_file: HashMap<usize, BTreeSet<String>> = HashMap::new();
    for (symbol_index, symbol) in scan.symbols.iter().enumerate() {
        if symbol_index % 256 == 0 {
            crate::repo_scan_policy::check_deadline()?;
        }
        if let Some(file_idx) = file_idx_by_path.get(&symbol.file_rel_path).copied() {
            if define_names_by_file
                .entry(file_idx)
                .or_default()
                .insert(symbol.name.clone())
            {
                crate::repo_scan_policy::charge_generated_work(
                    2,
                    symbol.name.len().saturating_mul(2),
                    "AST file definition index and output",
                )?;
                scan.files[file_idx].defines.push(symbol.name.clone());
            }
        }
    }
    Ok(())
}

fn resolve_routes_from_cache(cache: &AstScanCache, index: &Index, scan: &mut WorkspaceScan) -> Result<(), ScanError> {
    for (file_index, file) in cache.files.values().enumerate() {
        if file_index % 256 == 0 {
            crate::repo_scan_policy::check_deadline()?;
        }
        for (route_index, route) in file.routes.iter().enumerate() {
            if route_index % 256 == 0 {
                crate::repo_scan_policy::check_deadline()?;
            }
            let mut resolved_file = None;
            let mut resolved_line = None;
            let mut diag_reason = None;
            match index.by_simple.get(&route.handler_fn) {
                None => diag_reason = Some("not_found"),
                Some(candidates) => {
                    let same_crate = unique_candidate(candidates, |idx| index.defs[idx].crate_name == file.crate_name)?;
                    let pick = if same_crate.is_some() {
                        same_crate
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
                crate::repo_scan_policy::charge_generated_work(
                    1,
                    route
                        .method
                        .len()
                        .saturating_add(route.path.len())
                        .saturating_add(route.handler_fn.len())
                        .saturating_add(route.source_file.len())
                        .saturating_add(reason.len()),
                    "AST unresolved route output",
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
                "AST route output",
            )?;
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
    Ok(())
}

fn resolve_references(
    scan: &mut WorkspaceScan,
    index: &Index,
    file_idx_by_path: &HashMap<String, usize>,
) -> Result<(), ScanError> {
    type EdgeKey = (String, String, String);
    let mut per_file_edges: HashMap<usize, BTreeMap<EdgeKey, usize>> = HashMap::new();
    for (definition_index, from) in index.defs.iter().enumerate() {
        if definition_index % 256 == 0 {
            crate::repo_scan_policy::check_deadline()?;
        }
        let Some(from_idx) = file_idx_by_path.get(&from.file).copied() else {
            continue;
        };
        for (call_index, call) in from.calls.iter().enumerate() {
            if call_index % 256 == 0 {
                crate::repo_scan_policy::check_deadline()?;
            }
            let Some(target_idx) = index.resolve(call, from)? else {
                continue;
            };
            let target = &scan.symbols[index.defs[target_idx].symbol_idx];
            let key = (target.file_rel_path.clone(), target.name.clone(), from.simple.clone());
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
                        "AST reference edge index",
                    )?;
                    entry.insert(1);
                }
            }
        }
    }

    for (file_index, (from_idx, edges)) in per_file_edges.into_iter().enumerate() {
        if file_index % 256 == 0 {
            crate::repo_scan_policy::check_deadline()?;
        }
        let from_path = scan.files[from_idx].rel_path.clone();
        for ((to_file, to_symbol, from_symbol), call_count) in edges {
            crate::repo_scan_policy::charge_generated_work(
                1,
                to_file
                    .len()
                    .saturating_add(to_symbol.len())
                    .saturating_add(from_symbol.len()),
                "AST reference edge output",
            )?;
            scan.files[from_idx].references.push(FileReference {
                same_file: to_file == from_path,
                to_file,
                to_symbol,
                call_count,
                from_symbol: Some(from_symbol),
            });
        }
    }
    Ok(())
}

fn build_referenced_by(scan: &mut WorkspaceScan) -> Result<(), ScanError> {
    let mut inverse: HashMap<String, BTreeSet<String>> = HashMap::new();
    for (file_index, file) in scan.files.iter().enumerate() {
        if file_index % 256 == 0 {
            crate::repo_scan_policy::check_deadline()?;
        }
        for (reference_index, reference) in file.references.iter().enumerate() {
            if reference_index % 256 == 0 {
                crate::repo_scan_policy::check_deadline()?;
            }
            if !reference.same_file {
                let sources = inverse.entry(reference.to_file.clone()).or_default();
                if !sources.contains(&file.rel_path) {
                    crate::repo_scan_policy::charge_generated_work(
                        1,
                        reference.to_file.len().saturating_add(file.rel_path.len()),
                        "AST inverse reference index",
                    )?;
                    sources.insert(file.rel_path.clone());
                }
            }
        }
    }
    for (file_index, file) in scan.files.iter_mut().enumerate() {
        if file_index % 256 == 0 {
            crate::repo_scan_policy::check_deadline()?;
        }
        if let Some(set) = inverse.remove(&file.rel_path) {
            crate::repo_scan_policy::charge_generated_work(
                set.len(),
                set.iter().map(String::len).sum(),
                "AST inverse reference output",
            )?;
            file.referenced_by = set.into_iter().collect();
        }
    }
    Ok(())
}

fn compute_dead_code(scan: &mut WorkspaceScan, ident_refs: &HashMap<String, usize>) -> Result<(), ScanError> {
    let common_names: BTreeSet<&str> = [
        "new", "default", "len", "is_empty", "from", "into", "as_str", "as_ref", "clone", "drop", "fmt", "next",
        "iter", "build", "ok", "err", "some", "none", "main", "init",
    ]
    .iter()
    .copied()
    .collect();
    for (symbol_index, sym) in scan.symbols.iter().enumerate() {
        if symbol_index % 256 == 0 {
            crate::repo_scan_policy::check_deadline()?;
        }
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
            crate::repo_scan_policy::charge_generated_work(
                1,
                sym.crate_name
                    .len()
                    .saturating_add(sym.module_path.len())
                    .saturating_add(sym.file_rel_path.len())
                    .saturating_add(sym.kind.len())
                    .saturating_add(sym.name.len())
                    .saturating_add(64),
                "AST dead-code output",
            )?;
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
    Ok(())
}

/// Name the symbols that are referenced, but only ever from tests.
///
/// Runs after `compute_dead_code` and is deliberately disjoint from it: a
/// symbol with zero references anywhere is dead, not test-only. The distinction
/// an agent needs is between "nothing uses this" and "only its own test uses
/// this", and those call for different actions.
fn compute_test_only(
    scan: &mut WorkspaceScan,
    ident_refs: &HashMap<String, usize>,
    ident_refs_nontest: &HashMap<String, usize>,
) -> Result<(), ScanError> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for (symbol_index, sym) in scan.symbols.iter().enumerate() {
        if symbol_index % 256 == 0 {
            crate::repo_scan_policy::check_deadline()?;
        }
        if !sym.is_pub || sym.name.starts_with('_') || sym.name.len() < 4 {
            continue;
        }
        let all = ident_refs.get(&sym.name).copied().unwrap_or(0);
        let nontest = ident_refs_nontest.get(&sym.name).copied().unwrap_or(0);
        // `all > 0` excludes the genuinely dead; `nontest == 0` is the claim.
        // A definition site counts as a reference to itself in the non-test map
        // when the symbol lives outside a test scope, so a production symbol
        // never lands here on the strength of its own declaration alone.
        if all > 0 && nontest == 0 && !out.contains(&sym.name) {
            crate::repo_scan_policy::charge_generated_work(1, sym.name.len(), "AST test-only symbol index")?;
            out.insert(sym.name.clone());
        }
    }
    crate::repo_scan_policy::charge_generated_work(
        out.len(),
        out.iter().map(String::len).sum(),
        "AST test-only symbol output",
    )?;
    scan.test_only_symbols = out.into_iter().collect();
    Ok(())
}

fn roll_up_stats(scan: &mut WorkspaceScan) -> Result<(), ScanError> {
    let route_count = scan.routes.len();
    let file_reference_count = scan.files.iter().map(|f| f.references.len()).sum();
    let doc_coverage_files = scan.files.iter().filter(|f| f.doc_summary.is_some()).count();
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
        route_count,
        file_reference_count,
        external_dep_count: scan.external_deps.len(),
        doc_coverage_files,
        routes_by_crate,
    };
    Ok(())
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
    fn native_ast_scan_rejects_excessive_rust_generic_nesting() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_fixture(tmp.path());
        let nested = format!(
            "type Deep = {}u8{};\n",
            "Vec<".repeat(crate::workspace_scan::RUST_SYNTAX_MAX_DEPTH + 1),
            ">".repeat(crate::workspace_scan::RUST_SYNTAX_MAX_DEPTH + 1)
        );
        std::fs::write(tmp.path().join("crates/demo/src/a.rs"), nested).expect("nested source");

        let policy = crate::repo_scan_policy::RepoScanPolicy::for_exact_root(tmp.path()).expect("policy");
        let error = policy
            .execute(tmp.path(), run_scan_ast_at)
            .expect_err("native AST scan must reject nesting");
        assert!(error.to_string().contains("Rust syntax nesting"));
    }

    /// The three call shapes the M3 measurement found missing from a symbol's
    /// reference set. Each is written the way the real code writes it:
    ///
    ///   * a `crate::module::fn()` call from a **binary** crate (`main.rs`, no
    ///     `lib.rs`) — the shape at `corecruxd/src/main.rs:1432`;
    ///   * `x.field.method()` — the shape at `http/projections.rs:143`;
    ///   * `self.method()` — the shape at `crux-mcp/src/oauth.rs:91`.
    ///
    /// A missing reference makes `blast_radius` answer "nothing breaks" for a
    /// symbol that has callers, which is the worst shape a wrong answer can take.
    fn write_call_shape_fixture(root: &Path) {
        let crate_dir = root.join("crates/binbox");
        std::fs::create_dir_all(crate_dir.join("src")).expect("fixture dirs");
        std::fs::write(root.join("Cargo.toml"), "[workspace]\nmembers = [\"crates/binbox\"]\n")
            .expect("workspace toml");
        std::fs::write(
            crate_dir.join("Cargo.toml"),
            "[package]\nname = \"binbox\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .expect("crate toml");
        // Binary crate: main.rs and no lib.rs.
        std::fs::write(
            crate_dir.join("src/main.rs"),
            r#"//! Binary crate.
mod helper;
mod holder;

fn main() {
    let h = crate::holder::Holder::new();
    let _ = h.status.is_ready();
    let _ = h.describe();
}

async fn run() {
    tokio::spawn(async move {
        let Some(_s) = crate::helper::pick_signer(1) else {
            return;
        };
    });
}
"#,
        )
        .expect("main");
        std::fs::write(
            crate_dir.join("src/helper.rs"),
            r#"//! Helper module.
pub fn pick_signer(_timeout: u64) -> Option<u8> {
    None
}
"#,
        )
        .expect("helper");
        std::fs::write(
            crate_dir.join("src/holder.rs"),
            r#"//! Holder module.
pub struct Status;

impl Status {
    pub fn is_ready(&self) -> bool {
        true
    }
}

pub struct Holder {
    pub status: Status,
}

impl Holder {
    pub fn new() -> Self {
        Self { status: Status }
    }

    pub fn label(&self) -> &'static str {
        "holder"
    }

    pub fn describe(&self) -> String {
        self.label().to_string()
    }
}
"#,
        )
        .expect("holder");
    }

    fn refs_to(scan: &WorkspaceScan, symbol: &str) -> Vec<String> {
        scan.files
            .iter()
            .flat_map(|f| {
                f.references
                    .iter()
                    .filter(|r| r.to_symbol == symbol)
                    .map(move |r| format!("{}::{}", f.rel_path, r.from_symbol.clone().unwrap_or_default()))
            })
            .collect()
    }

    #[test]
    fn qualified_path_call_from_a_binary_crate_is_a_reference() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_call_shape_fixture(tmp.path());
        let scan = run_scan_ast_at(tmp.path()).expect("ast scan");
        let found = refs_to(&scan, "pick_signer");
        assert!(
            !found.is_empty(),
            "`crate::helper::pick_signer()` in a binary crate produced no reference — \
             blast_radius would report an empty radius for a symbol with a caller"
        );
    }

    #[test]
    fn method_through_a_field_is_a_reference() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_call_shape_fixture(tmp.path());
        let scan = run_scan_ast_at(tmp.path()).expect("ast scan");
        let found = refs_to(&scan, "is_ready");
        assert!(
            !found.is_empty(),
            "`h.status.is_ready()` produced no reference — the ident-counting blind spot"
        );
    }

    #[test]
    fn method_through_self_is_a_reference() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_call_shape_fixture(tmp.path());
        let scan = run_scan_ast_at(tmp.path()).expect("ast scan");
        let found = refs_to(&scan, "label");
        assert!(!found.is_empty(), "`self.label()` produced no reference");
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
        let assembled = normalize_scan(assemble_scan(tmp.path(), &cache).expect("assemble"));
        let fresh = normalize_scan(run_scan_ast_at(tmp.path()).expect("fresh scan"));
        assert!(!assembled.external_deps.is_empty());
        assert_eq!(assembled.stats.external_dep_count, assembled.external_deps.len());
        assert_eq!(
            serde_json::to_value(assembled).expect("assembled json"),
            serde_json::to_value(fresh).expect("fresh json")
        );
    }
}
