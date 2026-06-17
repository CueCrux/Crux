// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `corecruxctl code-health trace` — context-chain extractor (code-intelligence M4).
//!
//! Answers "what does this route/function touch?" by extracting the
//! endpoint → termination call path offline, with a `syn` walker (the M0
//! verdict: rust-analyzer SCIP was rejected). The M0 spike proved feasibility
//! but surfaced one limitation — **bare-name resolution is ambiguous** on
//! common idents (`new` → 18 defs). This production walker fixes that by
//! resolving against **module-qualified paths** (`crate::work::resolve_gate`,
//! `Ctx::new`) and stopping at a **termination boundary set** (store writes,
//! `problem_response`, serde, method/macro/external calls) so a chain stays
//! shallow and readable instead of exploding into plumbing.
//!
//! Pure, deterministic, CPU-only — `syn` is already in the lockfile. The
//! extractor never executes the target code.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};
use syn::visit::Visit;

type DynErr = Box<dyn std::error::Error + Send + Sync>;

/// How a call site was written — drives termination (methods/macros are leaves).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallKind {
    Func,
    Method,
    Macro,
}

/// A call reference captured from a fn body, in source order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallRef {
    /// Path segments for `Func` (e.g. `["crate","work","resolve_gate"]`); a
    /// single name for `Method` / `Macro`.
    pub segs: Vec<String>,
    pub kind: CallKind,
}

/// An indexed function definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FnDef {
    /// Module-qualified key, e.g. `http::work::post_gate_approve` or
    /// `auth::Ctx::new` for an inherent/trait method.
    pub qualified: String,
    pub simple: String,
    pub file: String,
    pub line: u32,
    pub calls: Vec<CallRef>,
}

/// The function index for a repo.
#[derive(Debug, Default)]
pub struct Index {
    pub defs: Vec<FnDef>,
    by_qualified: BTreeMap<String, usize>,
    by_simple: BTreeMap<String, Vec<usize>>,
}

impl Index {
    fn push(&mut self, def: FnDef) {
        let idx = self.defs.len();
        self.by_qualified.insert(def.qualified.clone(), idx);
        self.by_simple.entry(def.simple.clone()).or_default().push(idx);
        self.defs.push(def);
    }

    /// Resolve a call reference to a single def index, or an outcome describing
    /// why it is a termination.
    pub fn resolve(&self, c: &CallRef) -> Resolution {
        if c.kind != CallKind::Func {
            return Resolution::Boundary(if c.kind == CallKind::Method { "method" } else { "macro" });
        }
        let segs = normalize_segs(&c.segs);
        if segs.is_empty() {
            return Resolution::Boundary("external");
        }
        // Suffix match against qualified keys (kills the `new`/`drop` ambiguity).
        if segs.len() >= 2 {
            let suffix = segs.join("::");
            let hits: Vec<usize> = self
                .defs
                .iter()
                .enumerate()
                .filter(|(_, d)| d.qualified == suffix || d.qualified.ends_with(&format!("::{suffix}")))
                .map(|(i, _)| i)
                .collect();
            match hits.len() {
                1 => return Resolution::Def(hits[0]),
                0 => {}
                _ => return Resolution::Ambiguous(hits.len()),
            }
        }
        // Fall back to the trailing simple name (unambiguous only).
        let last = segs.last().cloned().unwrap_or_default();
        match self.by_simple.get(&last) {
            Some(v) if v.len() == 1 => Resolution::Def(v[0]),
            Some(v) if v.len() > 1 => Resolution::Ambiguous(v.len()),
            _ => Resolution::Boundary("external"),
        }
    }
}

/// Outcome of resolving a call reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    Def(usize),
    /// Resolvable name but more than one definition — we stop rather than guess.
    Ambiguous(usize),
    /// A leaf: method / macro / external / stdlib call.
    Boundary(&'static str),
}

/// Names that are *always* terminations even when locally resolvable — the
/// "what does this touch" boundary. Store writes, problem responses, and
/// serialization are the interesting leaves; recursing through them just adds
/// plumbing noise.
fn is_boundary_name(name: &str) -> bool {
    matches!(
        name,
        "problem_response" | "problem_for_status" | "into_response" | "store" | "write" | "read"
    ) || name.starts_with("write_")
        || name.ends_with("_response")
}

fn normalize_segs(segs: &[String]) -> Vec<String> {
    segs.iter()
        .filter(|s| !matches!(s.as_str(), "crate" | "self" | "super"))
        .cloned()
        .collect()
}

// ─────────────────────────── indexing ───────────────────────────

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
    let mut c = CallCollector { calls: vec![] };
    c.visit_block(block);
    c.calls
}

/// Derive a module path prefix from a repo-relative `.rs` path:
/// `crates/corecruxd/src/http/work.rs` → `http::work`;
/// `.../src/work.rs` → `work`; `.../mod.rs`|`lib.rs`|`main.rs` → the dir.
fn module_prefix(rel_path: &str) -> String {
    let p = rel_path.replace('\\', "/");
    let after_src = p.rsplit_once("/src/").map_or(p.as_str(), |(_, b)| b);
    let mut parts: Vec<&str> = after_src.split('/').collect();
    if let Some(last) = parts.pop() {
        let stem = last.strip_suffix(".rs").unwrap_or(last);
        if !matches!(stem, "mod" | "lib" | "main") {
            parts.push(stem);
        }
    }
    parts.join("::")
}

/// Parse one file's fns into `index`, qualifying by module prefix + `impl` type.
fn index_file(index: &mut Index, rel_path: &str, src: &str) {
    let file = match syn::parse_file(src) {
        Ok(f) => f,
        Err(_) => return,
    };
    let base = module_prefix(rel_path);
    index_items(index, &file.items, &base, rel_path, src);
}

fn qualify(base: &str, name: &str) -> String {
    if base.is_empty() {
        name.to_string()
    } else {
        format!("{base}::{name}")
    }
}

fn line_of(src: &str, name: &str) -> u32 {
    let needle = format!("fn {name}");
    for (i, l) in src.lines().enumerate() {
        if l.contains(&needle) {
            return (i + 1) as u32;
        }
    }
    0
}

fn index_items(index: &mut Index, items: &[syn::Item], base: &str, rel: &str, src: &str) {
    for item in items {
        match item {
            syn::Item::Fn(f) => {
                let simple = f.sig.ident.to_string();
                index.push(FnDef {
                    qualified: qualify(base, &simple),
                    simple: simple.clone(),
                    file: rel.to_string(),
                    line: line_of(src, &simple),
                    calls: collect_calls(&f.block),
                });
            }
            syn::Item::Mod(m) => {
                if let Some((_, inner)) = &m.content {
                    let nested = qualify(base, &m.ident.to_string());
                    index_items(index, inner, &nested, rel, src);
                }
            }
            syn::Item::Impl(im) => {
                let ty = impl_type_name(&im.self_ty);
                let ibase = match &ty {
                    Some(t) => qualify(base, t),
                    None => base.to_string(),
                };
                for ii in &im.items {
                    if let syn::ImplItem::Fn(f) = ii {
                        let simple = f.sig.ident.to_string();
                        index.push(FnDef {
                            qualified: qualify(&ibase, &simple),
                            simple: simple.clone(),
                            file: rel.to_string(),
                            line: line_of(src, &simple),
                            calls: collect_calls(&f.block),
                        });
                    }
                }
            }
            _ => {}
        }
    }
}

fn impl_type_name(ty: &syn::Type) -> Option<String> {
    if let syn::Type::Path(p) = ty {
        p.path.segments.last().map(|s| s.ident.to_string())
    } else {
        None
    }
}

/// Walk a repo and index every `.rs` fn (skips target/node_modules/.git).
pub fn index_repo(repo: &Path) -> Index {
    let mut index = Index::default();
    let mut stack = vec![repo.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if path.is_dir() {
                if !matches!(name.as_str(), "target" | "node_modules" | ".git" | ".worktrees") && !name.starts_with('.')
                {
                    stack.push(path);
                }
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let rel = path.strip_prefix(repo).unwrap_or(&path).to_string_lossy().to_string();
            if let Ok(src) = std::fs::read_to_string(&path) {
                index_file(&mut index, &rel, &src);
            }
        }
    }
    index
}

// ─────────────────────────── chain extraction ───────────────────────────

/// One node in an extracted chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainStep {
    pub name: String,
    pub qualified: String,
    pub file: String,
    pub line: u32,
    pub depth: usize,
    /// `call` (recursed into) or `termination` (leaf / boundary).
    pub kind: String,
    /// Why a step terminated (`store`, `method`, `ambiguous(3)`, …), if it did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// An extracted endpoint→termination chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Chain {
    pub schema: String,
    pub repo: String,
    pub root: String,
    pub commit_sha: String,
    pub steps: Vec<ChainStep>,
    /// Distinct termination labels (the interesting leaves: store writes, etc.).
    pub terminations: Vec<String>,
}

/// Extract the chain rooted at `root` (a simple fn name or qualified path).
pub fn extract_chain(index: &Index, repo: &str, commit_sha: &str, root: &str, max_depth: usize) -> Chain {
    let mut steps = Vec::new();
    let mut terminations: BTreeSet<String> = BTreeSet::new();
    let mut visited: BTreeSet<String> = BTreeSet::new();

    // resolve the root by qualified suffix or simple name
    let root_ref = CallRef {
        segs: root.split("::").map(|s| s.to_string()).collect(),
        kind: CallKind::Func,
    };
    match index.resolve(&root_ref) {
        Resolution::Def(i) => walk(index, i, 0, max_depth, &mut steps, &mut terminations, &mut visited),
        _ => {
            steps.push(ChainStep {
                name: root.to_string(),
                qualified: root.to_string(),
                file: String::new(),
                line: 0,
                depth: 0,
                kind: "termination".to_string(),
                note: Some("root not found".to_string()),
            });
        }
    }

    Chain {
        schema: "codechain.v1".to_string(),
        repo: repo.to_string(),
        root: root.to_string(),
        commit_sha: commit_sha.to_string(),
        steps,
        terminations: terminations.into_iter().collect(),
    }
}

#[allow(clippy::too_many_arguments)]
fn walk(
    index: &Index,
    def_idx: usize,
    depth: usize,
    max_depth: usize,
    steps: &mut Vec<ChainStep>,
    terminations: &mut BTreeSet<String>,
    visited: &mut BTreeSet<String>,
) {
    let def = &index.defs[def_idx];
    steps.push(ChainStep {
        name: def.simple.clone(),
        qualified: def.qualified.clone(),
        file: def.file.clone(),
        line: def.line,
        depth,
        kind: "call".to_string(),
        note: None,
    });
    if depth >= max_depth || !visited.insert(def.qualified.clone()) {
        return;
    }
    for c in &def.calls {
        let last = c.segs.last().cloned().unwrap_or_default();
        // Curated boundary: stop at store writes / problem responses even if local.
        if c.kind == CallKind::Func && is_boundary_name(&last) {
            push_termination(steps, terminations, &last, depth + 1, "boundary");
            continue;
        }
        match index.resolve(c) {
            Resolution::Def(i) => walk(index, i, depth + 1, max_depth, steps, terminations, visited),
            Resolution::Ambiguous(n) => {
                push_termination(steps, terminations, &last, depth + 1, &format!("ambiguous({n})"));
            }
            Resolution::Boundary(why) => {
                let label = match c.kind {
                    CallKind::Method => format!(".{last}"),
                    CallKind::Macro => format!("{last}!"),
                    CallKind::Func => last.clone(),
                };
                push_termination(steps, terminations, &label, depth + 1, why);
            }
        }
    }
}

fn push_termination(
    steps: &mut Vec<ChainStep>,
    terminations: &mut BTreeSet<String>,
    label: &str,
    depth: usize,
    why: &str,
) {
    terminations.insert(label.to_string());
    steps.push(ChainStep {
        name: label.to_string(),
        qualified: label.to_string(),
        file: String::new(),
        line: 0,
        depth,
        kind: "termination".to_string(),
        note: Some(why.to_string()),
    });
}

// ─────────────────────────── axum route table ───────────────────────────

/// A parsed `.route("/path", method(handler))` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteEntry {
    pub path: String,
    pub handler: String,
}

/// Parse axum route declarations from a router source file. Tolerant of the
/// multi-line form (`.route(\n "path",\n method(handler))`). Captures the
/// handler's trailing identifier (the fn the chain roots at).
pub fn parse_axum_routes(src: &str) -> Vec<RouteEntry> {
    let mut out = Vec::new();
    let bytes = src.as_bytes();
    let needle = ".route(";
    let mut i = 0;
    while let Some(rel) = src[i..].find(needle) {
        let start = i + rel + needle.len();
        // find the matching close paren for this .route( call
        let mut depth = 1usize;
        let mut j = start;
        while j < bytes.len() && depth > 0 {
            match bytes[j] {
                b'(' => depth += 1,
                b')' => depth -= 1,
                _ => {}
            }
            j += 1;
        }
        let inner = &src[start..j.saturating_sub(1)];
        if let Some(entry) = parse_route_inner(inner) {
            out.push(entry);
        }
        i = j;
    }
    out
}

fn parse_route_inner(inner: &str) -> Option<RouteEntry> {
    // path = first string literal
    let q1 = inner.find('"')?;
    let q2 = inner[q1 + 1..].find('"')? + q1 + 1;
    let path = inner[q1 + 1..q2].to_string();
    if !path.starts_with('/') {
        return None;
    }
    // handler = last identifier segment of the last `::`-path before a `)` or `,`
    // e.g. `get(self::work::get_pending_gates)` → get_pending_gates
    let after = &inner[q2 + 1..];
    let handler = after
        .rsplit("::")
        .next()
        .map(|s| s.trim_matches(|c: char| !c.is_alphanumeric() && c != '_').to_string())
        .filter(|s| !s.is_empty())?;
    if handler.is_empty() {
        return None;
    }
    Some(RouteEntry { path, handler })
}

/// Resolve a `--root` argument that may be a route path (`/v1/...`) or a fn
/// name. Returns the fn name to root the chain at.
pub fn resolve_root(root: &str, routes: &[RouteEntry]) -> String {
    if root.starts_with('/') {
        if let Some(r) = routes.iter().find(|r| r.path == root) {
            return r.handler.clone();
        }
    }
    root.to_string()
}

/// Slugify a root (route path or fn) into an entity id:
/// `/v1/work/gate/{actionId}/approve` → `v1-work-gate-actionId-approve`.
pub fn slugify_root(root: &str) -> String {
    let mut s: String = root
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    while s.contains("--") {
        s = s.replace("--", "-");
    }
    s.trim_matches('-').to_string()
}

/// Push a chain as a `codechain` entity: `PUT /v1/entities/codechain/{slug}`
/// with `{payload: <chain>}`. Idempotent — re-extract at the same commit
/// upserts the same payload.
pub fn push_chain(base: &str, token: Option<&str>, chain: &Chain) -> Result<String, DynErr> {
    let slug = slugify_root(&chain.root);
    let url = format!(
        "{}/v1/entities/codechain/{}",
        base.trim_end_matches('/'),
        urlencoding::encode(&slug)
    );
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(30)))
        .build()
        .into();
    let mut req = agent.put(&url);
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let resp = req.send_json(serde_json::json!({ "payload": chain }))?;
    let status = resp.status().as_u16();
    if status >= 400 {
        let body = resp.into_body().read_to_string().unwrap_or_default();
        return Err(format!("codechain entity write failed ({status}): {body}").into());
    }
    Ok(slug)
}

fn repo_routes(repo: &Path) -> Vec<RouteEntry> {
    let mut routes = Vec::new();
    for cand in ["crates/corecruxd/src/http/mod.rs", "src/http/mod.rs"] {
        if let Ok(s) = std::fs::read_to_string(repo.join(cand)) {
            routes.extend(parse_axum_routes(&s));
        }
    }
    routes
}

/// CLI entry for `corecruxctl code-health trace`.
pub fn run_trace(
    repo: &Path,
    root_arg: &str,
    format: &str,
    max_depth: usize,
    push: bool,
    http: &str,
    token_file: Option<&Path>,
) -> Result<(), DynErr> {
    if !repo.exists() {
        return Err(format!("repo does not exist: {}", repo.display()).into());
    }
    let index = index_repo(repo);
    let slug = repo
        .canonicalize()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
        .unwrap_or_else(|| "repo".to_string());
    let commit_sha = crate::code_health::short_sha(repo);

    let routes = repo_routes(repo);
    let root = resolve_root(root_arg, &routes);
    let chain = extract_chain(&index, &slug, &commit_sha, &root, max_depth);

    if push {
        let token = crate::code_health::resolve_token(token_file);
        let id = push_chain(http, token.as_deref(), &chain)?;
        println!(
            "pushed codechain entity {id} ({} steps, root {})",
            chain.steps.len(),
            chain.root
        );
        return Ok(());
    }

    match format {
        "text" => {
            println!("Chain — {} · root {} @ {}", chain.repo, chain.root, chain.commit_sha);
            println!("==================================================");
            for s in &chain.steps {
                let indent = "  ".repeat(s.depth);
                let loc = if s.line > 0 {
                    format!("  ({}:{})", s.file, s.line)
                } else {
                    String::new()
                };
                let note = s.note.as_deref().map(|n| format!("  [{n}]")).unwrap_or_default();
                println!("{indent}{}{loc}{note}", s.name);
            }
            println!("\nterminations: {}", chain.terminations.join(", "));
        }
        _ => println!("{}", serde_json::to_string_pretty(&chain)?),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = r#"
pub mod work {
    pub fn resolve_gate(s: &mut Store) -> bool {
        let g = get_gate(s);
        write_gate(s, g);
        s.store();
        true
    }
    fn get_gate(s: &Store) -> u8 { s.read() }
    fn write_gate(s: &mut Store, g: u8) { s.write() }
}
pub mod http {
    use crate::work;
    pub fn post_gate_approve(s: &mut Store) -> Resp {
        if let Err(e) = require_scopes(s) { return problem_response(e); }
        let r = crate::work::resolve_gate(s);
        now_ms();
        problem_response(r)
    }
    fn require_scopes(s: &Store) -> Result<(), E> { Ok(()) }
}
struct Ctx;
impl Ctx { fn new() -> Ctx { Ctx } }
fn now_ms() -> u64 { 0 }
fn problem_response(x: impl Sized) -> Resp { Resp }
"#;

    fn idx() -> Index {
        let mut i = Index::default();
        index_file(&mut i, "crates/corecruxd/src/lib.rs", FIXTURE);
        i
    }

    #[test]
    fn module_prefix_derivation() {
        assert_eq!(module_prefix("crates/corecruxd/src/http/work.rs"), "http::work");
        assert_eq!(module_prefix("crates/corecruxd/src/work.rs"), "work");
        assert_eq!(module_prefix("crates/corecruxd/src/http/mod.rs"), "http");
        assert_eq!(module_prefix("crates/x/src/lib.rs"), "");
    }

    #[test]
    fn qualified_resolution_kills_ambiguity() {
        let index = idx();
        // resolve_gate is reachable and qualified
        let chain = extract_chain(&index, "corecruxd", "sha", "post_gate_approve", 6);
        let names: Vec<&str> = chain.steps.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"post_gate_approve"));
        assert!(
            names.contains(&"resolve_gate"),
            "qualified crate::work::resolve_gate resolved: {names:?}"
        );
        assert!(names.contains(&"require_scopes"));
        // store write + problem_response are terminations, not recursed-through
        assert!(
            chain.terminations.iter().any(|t| t == ".store"),
            "store write is a termination: {:?}",
            chain.terminations
        );
        assert!(
            chain.terminations.iter().any(|t| t == "problem_response"),
            "problem_response is a boundary: {:?}",
            chain.terminations
        );
    }

    #[test]
    fn boundary_names_terminate_even_if_local() {
        // write_gate is local but write_* is a boundary → resolve_gate's body
        // reaches it as a termination, never recursing into its `.write()`.
        assert!(is_boundary_name("write_gate"));
        assert!(is_boundary_name("problem_response"));
        assert!(!is_boundary_name("resolve_gate"));
    }

    #[test]
    fn cycle_and_depth_guard() {
        let index = idx();
        let chain = extract_chain(&index, "r", "s", "post_gate_approve", 1);
        // depth cap 1 → root + its direct callees only
        assert!(chain.steps.iter().all(|s| s.depth <= 2));
    }

    #[test]
    fn axum_route_parse_singleline_and_multiline() {
        let src = r#"
            .route("/v1/work/gate/pending", get(self::work::get_pending_gates))
            .route(
                "/v1/work/gate/{actionId}/approve",
                axum::routing::post(self::work::post_gate_approve),
            )
            .route("/v1/x", get(noise))
        "#;
        let routes = parse_axum_routes(src);
        assert_eq!(routes.len(), 3);
        let approve = routes
            .iter()
            .find(|r| r.path.contains("approve"))
            .expect("approve route");
        assert_eq!(approve.handler, "post_gate_approve");
        let pending = routes
            .iter()
            .find(|r| r.path.contains("pending"))
            .expect("pending route");
        assert_eq!(pending.handler, "get_pending_gates");
    }

    #[test]
    fn resolve_root_maps_route_to_handler() {
        let routes = vec![RouteEntry {
            path: "/v1/work/gate/{id}/approve".into(),
            handler: "post_gate_approve".into(),
        }];
        assert_eq!(resolve_root("/v1/work/gate/{id}/approve", &routes), "post_gate_approve");
        assert_eq!(resolve_root("post_gate_approve", &routes), "post_gate_approve");
        // Unknown route path falls through to itself.
        assert_eq!(resolve_root("/v1/unknown", &routes), "/v1/unknown");
    }

    #[test]
    fn slugify_root_collapses_non_alnum_runs() {
        assert_eq!(
            slugify_root("/v1/work/gate/{actionId}/approve"),
            "v1-work-gate-actionId-approve"
        );
        // `_` is not alphanumeric → becomes `-`.
        assert_eq!(slugify_root("post_gate_approve"), "post-gate-approve");
        assert_eq!(slugify_root("///a//b///"), "a-b");
    }

    #[test]
    fn parse_route_inner_rejects_non_path_and_missing_literal() {
        // No leading slash → rejected.
        assert!(parse_axum_routes(r#".route("notapath", get(h))"#.into()).is_empty());
        // No string literal at all → rejected.
        assert!(parse_axum_routes(r#".route(foo, get(h))"#.into()).is_empty());
    }

    #[test]
    fn resolve_handles_methods_macros_and_ambiguity() {
        let mut i = Index::default();
        // Two defs sharing the simple name `new` under different modules.
        index_file(
            &mut i,
            "crates/corecruxd/src/a.rs",
            "struct A; impl A { fn build() -> A { A } }\nstruct B; impl B { fn build() -> B { B } }",
        );
        // method/macro calls always terminate.
        assert_eq!(
            i.resolve(&CallRef {
                segs: vec!["foo".into()],
                kind: CallKind::Method
            }),
            Resolution::Boundary("method")
        );
        assert_eq!(
            i.resolve(&CallRef {
                segs: vec!["bar".into()],
                kind: CallKind::Macro
            }),
            Resolution::Boundary("macro")
        );
        // empty after normalisation → external.
        assert_eq!(
            i.resolve(&CallRef {
                segs: vec!["crate".into()],
                kind: CallKind::Func
            }),
            Resolution::Boundary("external")
        );
        // ambiguous simple name (`build` defined twice).
        assert_eq!(
            i.resolve(&CallRef {
                segs: vec!["build".into()],
                kind: CallKind::Func
            }),
            Resolution::Ambiguous(2)
        );
        // unknown name → external boundary.
        assert_eq!(
            i.resolve(&CallRef {
                segs: vec!["nope".into()],
                kind: CallKind::Func
            }),
            Resolution::Boundary("external")
        );
    }

    #[test]
    fn extract_chain_root_not_found_emits_single_termination() {
        let index = idx();
        let chain = extract_chain(&index, "r", "s", "does_not_exist", 5);
        assert_eq!(chain.steps.len(), 1);
        assert_eq!(chain.steps[0].kind, "termination");
        assert_eq!(chain.steps[0].note.as_deref(), Some("root not found"));
    }

    fn tmp_repo() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("crux-cc-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(d.join("crates/corecruxd/src/http")).unwrap();
        std::fs::create_dir_all(d.join("target")).unwrap();
        std::fs::write(d.join("crates/corecruxd/src/lib.rs"), FIXTURE).unwrap();
        std::fs::write(
            d.join("crates/corecruxd/src/http/mod.rs"),
            r#"Router::new().route("/v1/gate/approve", post(self::work::post_gate_approve))"#,
        )
        .unwrap();
        std::fs::write(d.join("target/ignored.rs"), "fn ignored() {}").unwrap();
        d
    }

    #[test]
    fn index_repo_walks_rs_files_and_skips_target() {
        let repo = tmp_repo();
        let index = index_repo(&repo);
        // post_gate_approve from lib.rs is indexed; target/ is skipped.
        assert!(index.defs.iter().any(|d| d.simple == "post_gate_approve"));
        assert!(!index.defs.iter().any(|d| d.simple == "ignored"));
    }

    #[test]
    fn run_trace_text_and_json_without_push() {
        let repo = tmp_repo();
        // Root via a route path → resolved to the handler.
        run_trace(&repo, "/v1/gate/approve", "text", 4, false, "http://127.0.0.1:1", None).unwrap();
        run_trace(&repo, "post_gate_approve", "json", 4, false, "http://127.0.0.1:1", None).unwrap();
        // Missing repo → Err.
        assert!(run_trace(
            &repo.join("nope"),
            "post_gate_approve",
            "json",
            4,
            false,
            "http://127.0.0.1:1",
            None
        )
        .is_err());
    }

    #[test]
    fn push_chain_succeeds_and_run_trace_push_path() {
        let chain = extract_chain(&idx(), "r", "sha", "post_gate_approve", 4);
        let (port, h) = crate::test_support::serve_responses(vec![(200, "{}".to_string())]);
        let slug = push_chain(&format!("http://127.0.0.1:{port}"), Some("tok"), &chain).expect("push ok");
        let reqs = h.join().unwrap();
        assert_eq!(slug, "post-gate-approve");
        assert!(reqs[0].starts_with("PUT /v1/entities/codechain/post-gate-approve"));
        assert!(reqs[0].to_lowercase().contains("authorization: bearer tok"));

        // run_trace with push=true drives index→extract→push.
        let repo = tmp_repo();
        let (port, h) = crate::test_support::serve_responses(vec![(200, "{}".to_string())]);
        run_trace(
            &repo,
            "post_gate_approve",
            "json",
            4,
            true,
            &format!("http://127.0.0.1:{port}"),
            None,
        )
        .unwrap();
        h.join().ok();
    }

    #[test]
    fn push_chain_transport_error_on_dead_port() {
        let chain = extract_chain(&idx(), "r", "sha", "post_gate_approve", 4);
        assert!(push_chain("http://127.0.0.1:1", None, &chain).is_err());
    }
}
