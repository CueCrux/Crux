// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
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
    walk_dir, CrateInfo, DeadSymbol, DepEdge, FileInfo, FileReference, RouteHit, ScanDiagnostics, ScanError, ScanStats,
    StubHit, SymbolInfo, UnresolvedRoute, WorkspaceScan,
};

pub(crate) fn run_scan_ast_at(root: &Path) -> Result<WorkspaceScan, ScanError> {
    let started_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    let started_inst = std::time::Instant::now();
    let scan_id = format!("ws_{started_ms}");

    let mut scan = WorkspaceScan {
        scan_id,
        root_path: root.display().to_string(),
        started_at_unix_ms: started_ms,
        diagnostics: ScanDiagnostics::default(),
        ..Default::default()
    };

    let workspace = discover_workspace(root)?;
    let known_crate_names: BTreeSet<String> = workspace.crate_dirs.keys().cloned().collect();
    let mut index = Index::default();
    let mut file_idx_by_path: HashMap<String, usize> = HashMap::new();
    let mut ident_refs: HashMap<String, usize> = HashMap::new();

    for (cname, files) in &workspace.files_by_crate {
        let Some(crate_root) = workspace.crate_dirs.get(cname) else {
            continue;
        };
        let mut crate_loc = 0usize;
        let mut crate_file_count = 0usize;

        for abs in files {
            let rel = abs.strip_prefix(root).map_or_else(|_| abs.clone(), Path::to_path_buf);
            let rel_str = rel.display().to_string();
            let module_path = crate::workspace_scan::infer_module_path(cname, crate_root, abs);
            let src = std::fs::read_to_string(abs).unwrap_or_default();
            let loc = src.lines().count();
            let (doc_full, doc_summary) = parse_file_doc_header(&src);
            let is_test_file = crate::workspace_scan::looks_like_test_file(&rel_str, &src);
            let file_idx = scan.files.len();
            file_idx_by_path.insert(rel_str.clone(), file_idx);

            crate_loc += loc;
            crate_file_count += 1;
            scan.files.push(FileInfo {
                rel_path: rel_str.clone(),
                crate_name: cname.clone(),
                module_path: module_path.clone(),
                loc,
                symbol_count: 0,
                stub_count: 0,
                doc_summary,
                doc_full,
                defines: Vec::new(),
                references: Vec::new(),
                referenced_by: Vec::new(),
                is_test_file,
            });

            let is_scanner_source = rel_str.ends_with("corecruxd/src/workspace_scan.rs")
                || rel_str.ends_with("corecruxd/src/workspace_scan_ast.rs");
            if !is_scanner_source {
                for (line_no, line) in src.lines().enumerate() {
                    if let Some((kind, snippet)) = parse_stub_line(line) {
                        scan.stubs.push(StubHit {
                            crate_name: cname.clone(),
                            file_rel_path: rel_str.clone(),
                            line: line_no + 1,
                            kind: kind.to_string(),
                            snippet,
                        });
                        scan.files[file_idx].stub_count += 1;
                    }
                }
            }

            let parsed = match syn::parse_file(&src) {
                Ok(parsed) => parsed,
                Err(_) => continue,
            };
            collect_identifier_refs(&parsed, &mut ident_refs);
            let mut line_lookup = LineLookup::new(&src);
            index_items(
                &mut scan,
                &mut index,
                &mut file_idx_by_path,
                &known_crate_names,
                &mut line_lookup,
                &parsed.items,
                FileCtx {
                    crate_name: cname,
                    crate_root,
                    rel_path: &rel_str,
                    module_path: &module_path,
                    file_idx,
                },
            );
        }

        let crate_root = crate_root.clone();
        scan.crates.push(CrateInfo {
            name: cname.clone(),
            rel_path: crate_root
                .strip_prefix(root)
                .map_or_else(|_| crate_root.display().to_string(), |p| p.display().to_string()),
            internal_deps: workspace.crate_internal_deps.get(cname).cloned().unwrap_or_default(),
            file_count: crate_file_count,
            total_loc: crate_loc,
        });
    }

    denormalize_defines(&mut scan, &file_idx_by_path);
    resolve_routes(root, &workspace, &index, &mut scan, &file_idx_by_path);
    resolve_references(&mut scan, &index, &file_idx_by_path);
    build_referenced_by(&mut scan);
    compute_dead_code(&mut scan, &ident_refs);
    roll_up_stats(&mut scan);

    let elapsed_ms = started_inst.elapsed().as_millis() as u64;
    scan.finished_at_unix_ms = scan.started_at_unix_ms + elapsed_ms;
    scan.duration_ms = elapsed_ms;
    Ok(scan)
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
    file_idx: usize,
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

fn index_items(
    scan: &mut WorkspaceScan,
    index: &mut Index,
    file_idx_by_path: &mut HashMap<String, usize>,
    known_crates: &BTreeSet<String>,
    line_lookup: &mut LineLookup,
    items: &[syn::Item],
    ctx: FileCtx<'_>,
) {
    for item in items {
        match item {
            syn::Item::Fn(f) => {
                let name = f.sig.ident.to_string();
                let symbol_idx = push_symbol(scan, ctx, line_lookup, "fn", &name, is_pub(&f.vis));
                index.push(FnDef {
                    qualified: qualify(ctx.module_path, &name),
                    simple: name,
                    crate_name: ctx.crate_name.to_string(),
                    module_path: ctx.module_path.to_string(),
                    file: ctx.rel_path.to_string(),
                    symbol_idx,
                    calls: collect_calls(&f.block),
                });
            }
            syn::Item::Struct(s) => {
                let name = s.ident.to_string();
                push_symbol(scan, ctx, line_lookup, "struct", &name, is_pub(&s.vis));
            }
            syn::Item::Enum(e) => {
                let name = e.ident.to_string();
                push_symbol(scan, ctx, line_lookup, "enum", &name, is_pub(&e.vis));
            }
            syn::Item::Trait(t) => {
                let name = t.ident.to_string();
                push_symbol(scan, ctx, line_lookup, "trait", &name, is_pub(&t.vis));
            }
            syn::Item::Type(t) => {
                let name = t.ident.to_string();
                push_symbol(scan, ctx, line_lookup, "type", &name, is_pub(&t.vis));
            }
            syn::Item::Const(c) => {
                let name = c.ident.to_string();
                push_symbol(scan, ctx, line_lookup, "const", &name, is_pub(&c.vis));
            }
            syn::Item::Static(s) => {
                let name = s.ident.to_string();
                push_symbol(scan, ctx, line_lookup, "static", &name, is_pub(&s.vis));
            }
            syn::Item::Mod(m) => {
                let name = m.ident.to_string();
                push_symbol(scan, ctx, line_lookup, "mod", &name, is_pub(&m.vis));
                if let Some((_, inner)) = &m.content {
                    let nested = qualify(ctx.module_path, &name);
                    let nested_ctx = FileCtx {
                        module_path: &nested,
                        ..ctx
                    };
                    index_items(
                        scan,
                        index,
                        file_idx_by_path,
                        known_crates,
                        line_lookup,
                        inner,
                        nested_ctx,
                    );
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
                        let symbol_idx = push_symbol(scan, ctx, line_lookup, "fn", &name, is_pub(&f.vis));
                        index.push(FnDef {
                            qualified: qualify(&impl_base, &name),
                            simple: name,
                            crate_name: ctx.crate_name.to_string(),
                            module_path: ctx.module_path.to_string(),
                            file: ctx.rel_path.to_string(),
                            symbol_idx,
                            calls: collect_calls(&f.block),
                        });
                    }
                }
            }
            syn::Item::Use(u) => {
                for raw in use_tree_paths(&u.tree) {
                    if let Some(to_module) = use_path_to_module(&raw, ctx.crate_name, known_crates) {
                        scan.deps.push(DepEdge {
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
    let _ = file_idx_by_path;
}

fn push_symbol(
    scan: &mut WorkspaceScan,
    ctx: FileCtx<'_>,
    line_lookup: &mut LineLookup,
    kind: &str,
    name: &str,
    is_pub: bool,
) -> usize {
    let symbol_idx = scan.symbols.len();
    scan.symbols.push(SymbolInfo {
        crate_name: ctx.crate_name.to_string(),
        module_path: ctx.module_path.to_string(),
        file_rel_path: ctx.rel_path.to_string(),
        line: line_lookup.take(kind, name),
        kind: kind.to_string(),
        name: name.to_string(),
        is_pub,
    });
    scan.files[ctx.file_idx].symbol_count += 1;
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

fn resolve_routes(
    root: &Path,
    workspace: &WorkspaceFiles,
    index: &Index,
    scan: &mut WorkspaceScan,
    _file_idx_by_path: &HashMap<String, usize>,
) {
    for (cname, files) in &workspace.files_by_crate {
        for abs in files {
            let rel = abs.strip_prefix(root).map_or_else(|_| abs.clone(), Path::to_path_buf);
            let rel_str = rel.display().to_string();
            let src = std::fs::read_to_string(abs).unwrap_or_default();
            if !src.contains(".route(") {
                continue;
            }
            for route in parse_routes_in_source(&src, &rel_str) {
                let mut resolved_file = None;
                let mut resolved_line = None;
                let mut diag_reason = None;
                match index.by_simple.get(&route.handler_fn) {
                    None => diag_reason = Some("not_found"),
                    Some(candidates) => {
                        let same_crate: Vec<usize> = candidates
                            .iter()
                            .copied()
                            .filter(|idx| index.defs[*idx].crate_name == *cname)
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
                    method: route.method,
                    path: route.path,
                    handler_fn: route.handler_fn,
                    handler_file: resolved_file,
                    handler_line: resolved_line,
                    source_file: route.source_file,
                    source_line: route.source_line,
                });
            }
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
        doc_coverage_files,
        routes_by_crate,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
