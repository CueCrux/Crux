// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Polyglot code-structure scanner backed by tree-sitter for non-Rust files.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use tree_sitter::{Node, Parser};

use crate::workspace_scan::{
    parse_file_doc_header, parse_internal_path_deps, walk_dir, CrateInfo, DepEdge, FileInfo, FileReference,
    ScanDiagnostics, ScanError, ScanStats, SymbolInfo, WorkspaceScan,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LanguageKind {
    Rust,
    TypeScript,
    Tsx,
    Python,
    Vue,
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
    deps: Vec<DepEdge>,
    calls: Vec<CallSite>,
}

#[derive(Debug, Clone)]
struct CallSite {
    name: String,
    from_symbol: Option<String>,
}

pub(crate) fn run_repo_scan_at(root: &Path) -> Result<WorkspaceScan, ScanError> {
    if should_use_rust_workspace_scan(root) {
        return crate::workspace_scan::run_scan_at(root);
    }
    if has_rust_workspace(root) {
        // Cargo workspace + polyglot files: scan the cargo tree natively so
        // crate structure and route extraction survive, then merge the
        // tree-sitter extraction of the non-Rust files on top. Without this a
        // single stray .ts/.py file used to flatten a 28-crate workspace into
        // one package with zero routes.
        let mut scan = crate::workspace_scan::run_scan_at(root)?;
        let poly = run_polyglot_scan_inner(root, false)?;
        merge_polyglot_scan(&mut scan, poly);
        return Ok(scan);
    }
    run_polyglot_scan_at(root)
}

pub(crate) fn has_rust_workspace(root: &Path) -> bool {
    root.join("Cargo.toml").exists() && has_supported_file(root, &[Some("rs")])
}

pub(crate) fn should_use_rust_workspace_scan(root: &Path) -> bool {
    has_rust_workspace(root) && !has_polyglot_non_rust_files(root)
}

/// Fold a rust-excluded polyglot scan into a native Rust workspace scan.
/// Crates, routes, stubs and dead-code stay authoritative from the Rust side;
/// files/symbols/deps are unioned and the stats re-rolled from the merged
/// contents.
fn merge_polyglot_scan(scan: &mut WorkspaceScan, poly: WorkspaceScan) {
    let existing: std::collections::BTreeSet<String> = scan.crates.iter().map(|c| c.name.clone()).collect();
    scan.crates
        .extend(poly.crates.into_iter().filter(|c| !existing.contains(&c.name)));
    scan.files.extend(poly.files);
    scan.symbols.extend(poly.symbols);
    scan.deps.extend(poly.deps);
    scan.duration_ms += poly.duration_ms;
    scan.finished_at_unix_ms = scan.finished_at_unix_ms.max(poly.finished_at_unix_ms);
    roll_up_stats(scan);
}

pub(crate) fn run_polyglot_scan_at(root: &Path) -> Result<WorkspaceScan, ScanError> {
    run_polyglot_scan_inner(root, true)
}

fn run_polyglot_scan_inner(root: &Path, include_rust: bool) -> Result<WorkspaceScan, ScanError> {
    let started_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    let started_inst = std::time::Instant::now();
    let package_name = discover_package_name(root);
    let files = supported_files(root, include_rust)?;
    let mut extracted = Vec::new();
    for (abs, lang) in files {
        if let Some(file) = extract_file(root, &abs, lang, &package_name)? {
            extracted.push(file);
        }
    }

    let mut scan = WorkspaceScan {
        scan_id: format!("ws_{started_ms}"),
        root_path: root.display().to_string(),
        started_at_unix_ms: started_ms,
        diagnostics: ScanDiagnostics::default(),
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
    roll_up_stats(&mut scan);
    let elapsed_ms = started_inst.elapsed().as_millis() as u64;
    scan.finished_at_unix_ms = scan.started_at_unix_ms + elapsed_ms;
    scan.duration_ms = elapsed_ms;
    Ok(scan)
}

fn supported_files(root: &Path, include_rust: bool) -> Result<Vec<(PathBuf, LanguageKind)>, ScanError> {
    let mut files = Vec::new();
    walk_dir(root, root, &mut |_rel, abs| {
        if let Some(lang) = language_for_path(abs) {
            if include_rust || lang != LanguageKind::Rust {
                files.push((abs.to_path_buf(), lang));
            }
        }
    })?;
    files.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(files)
}

fn language_for_path(path: &Path) -> Option<LanguageKind> {
    match path.extension().and_then(|e| e.to_str()).unwrap_or_default() {
        "rs" => Some(LanguageKind::Rust),
        "ts" => Some(LanguageKind::TypeScript),
        "tsx" => Some(LanguageKind::Tsx),
        "py" => Some(LanguageKind::Python),
        "vue" => Some(LanguageKind::Vue),
        _ => None,
    }
}

fn extract_file(
    root: &Path,
    abs: &Path,
    lang: LanguageKind,
    package_name: &str,
) -> Result<Option<ExtractedFile>, ScanError> {
    let src = std::fs::read_to_string(abs).unwrap_or_default();
    let rel_path = rel_string(root, abs);
    let loc = src.lines().count();
    let (doc_full, doc_summary) = parse_file_doc_header(&src);
    let is_test_file = crate::workspace_scan::looks_like_test_file(&rel_path, &src)
        || rel_path.ends_with(".test.ts")
        || rel_path.ends_with(".spec.ts")
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
        deps: Vec::new(),
        calls: Vec::new(),
    };

    match lang {
        LanguageKind::Rust => extract_rust_file(&src, &mut file),
        LanguageKind::TypeScript => extract_ts_block(&src, 0, false, &mut file)?,
        LanguageKind::Tsx => extract_ts_block(&src, 0, true, &mut file)?,
        LanguageKind::Python => extract_python_file(&src, &mut file)?,
        LanguageKind::Vue => {
            for block in vue_script_blocks(&src) {
                extract_ts_block(&block.text, block.start_line_offset, false, &mut file)?;
            }
        }
    }
    Ok(Some(file))
}

fn extract_rust_file(src: &str, file: &mut ExtractedFile) {
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
                for raw in rust_use_paths(&u.tree) {
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

fn extract_ts_block(src: &str, line_offset: usize, tsx: bool, file: &mut ExtractedFile) -> Result<(), ScanError> {
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
    walk_ts_node(tree.root_node(), bytes, line_offset, file, None, false);
    Ok(())
}

fn walk_ts_node(
    node: Node<'_>,
    src: &[u8],
    line_offset: usize,
    file: &mut ExtractedFile,
    current_fn: Option<String>,
    exported: bool,
) {
    let kind = node.kind();
    let is_export = exported || kind == "export_statement";
    match kind {
        "function_declaration" | "function_signature" => {
            if let Some(name) = field_ident(node, src, "name") {
                push_symbol(
                    file,
                    "fn",
                    &name,
                    line_offset + node.start_position().row + 1,
                    is_export || !name.starts_with('_'),
                );
                walk_children(node, src, line_offset, file, Some(name), is_export);
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
                walk_children(node, src, line_offset, file, Some(name), is_export);
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
            if is_export {
                for name in identifiers_under(node, src) {
                    push_symbol(file, "const", &name, line_offset + node.start_position().row + 1, true);
                }
            }
        }
        "import_statement" => {
            if let Some(module) = quoted_child_text(node, src) {
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
                        name,
                        from_symbol: current_fn.clone(),
                    });
                }
            }
        }
        _ => {}
    }
    walk_children(node, src, line_offset, file, current_fn, is_export);
}

fn walk_children(
    node: Node<'_>,
    src: &[u8],
    line_offset: usize,
    file: &mut ExtractedFile,
    current_fn: Option<String>,
    exported: bool,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_ts_node(child, src, line_offset, file, current_fn.clone(), exported);
    }
}

fn extract_python_file(src: &str, file: &mut ExtractedFile) -> Result<(), ScanError> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .map_err(|err| ScanError::Io(std::io::Error::other(err.to_string())))?;
    let Some(tree) = parser.parse(src, None) else {
        return Ok(());
    };
    let bytes = src.as_bytes();
    walk_py_node(tree.root_node(), bytes, file, None);
    Ok(())
}

fn walk_py_node(node: Node<'_>, src: &[u8], file: &mut ExtractedFile, current_fn: Option<String>) {
    match node.kind() {
        "function_definition" => {
            if let Some(name) = field_ident(node, src, "name") {
                push_symbol(file, "fn", &name, node.start_position().row + 1, !name.starts_with('_'));
                walk_py_children(node, src, file, Some(name));
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
        }
        _ => {}
    }
    walk_py_children(node, src, file, current_fn);
}

fn walk_py_children(node: Node<'_>, src: &[u8], file: &mut ExtractedFile, current_fn: Option<String>) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_py_node(child, src, file, current_fn.clone());
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
    if name.is_empty() || file.symbols.iter().any(|s| s.name == name && s.kind == kind) {
        return;
    }
    file.symbols.push(SymbolInfo {
        crate_name: file.package_name.clone(),
        module_path: file.module_path.clone(),
        file_rel_path: file.rel_path.clone(),
        line,
        kind: kind.to_string(),
        name: name.to_string(),
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

fn has_polyglot_non_rust_files(root: &Path) -> bool {
    has_supported_file(root, &[Some("ts"), Some("tsx"), Some("py"), Some("vue")])
}

fn rel_string(root: &Path, abs: &Path) -> String {
    abs.strip_prefix(root)
        .map_or_else(|_| abs.to_path_buf(), Path::to_path_buf)
        .display()
        .to_string()
}

fn module_path(package_name: &str, rel_path: &str) -> String {
    let clean = rel_path
        .trim_end_matches(".ts")
        .trim_end_matches(".tsx")
        .trim_end_matches(".py")
        .trim_end_matches(".vue")
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

fn quoted_child_text(node: Node<'_>, src: &[u8]) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        let text = node_text(child, src);
        if (text.starts_with('"') && text.ends_with('"')) || (text.starts_with('\'') && text.ends_with('\'')) {
            return Some(text.trim_matches('"').trim_matches('\'').to_string());
        }
        if let Some(inner) = quoted_child_text(child, src) {
            return Some(inner);
        }
    }
    None
}

fn identifiers_under(node: Node<'_>, src: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    if node.kind() == "identifier" {
        out.push(node_text(node, src));
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        out.extend(identifiers_under(child, src));
    }
    out
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

fn rust_use_paths(tree: &syn::UseTree) -> Vec<String> {
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
